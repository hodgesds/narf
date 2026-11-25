# drivers/gpu/intel_gpu — Specification

> Status: **v1.14**. Display and GT driver for Intel graphics from Gen9
> (Skylake, Broxton/Gemini Lake) through Nova Lake-S display 35, plus the
> discrete DG1, Arc Alchemist, Arctic Sound-M and Battlemage. Opt-in paths
> name their `narf.intel.*` boot option where they are described. Native
> fixtures, not silicon, validate most of it. Earlier versions are in git.
>
> References include Intel PRMs and the cited MIT-licensed Linux i915/xe ABI,
> command and register definitions.

## 1. Why this is feasible

The 2026 audit confirmed that Intel publishes the per-generation
**Programmer's Reference Manuals (PRMs)** as multi-volume public
PDFs, with the most thorough coverage on older generations and a
narrowing surface as the generation gets newer:

| Generation                | PRM coverage                                         | Verdict                |
| ------------------------- | ---------------------------------------------------- | ---------------------- |
| Tiger Lake (Gen12 Xe-LP)  | full multi-volume PRMs                               | full driver feasible   |
| Rocket Lake (Gen12 Xe-LP) | Gen12 PRMs plus Linux's exact pre-GMD platform data  | GT feasible; display separately qualifies |
| Alder Lake / Raptor Lake  | full PRMs (Gen12 carries forward)                    | full driver feasible   |
| Meteor Lake (Xe-LPG)      | display + media PRMs published; 3D / compute thinner | display / KMS feasible |
| Lunar Lake (Xe2)          | architecture whitepapers only as of mid-2026        | driven from Linux i915/xe source |

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
| 2a  | Command Reference: Instructions      | `intel_gpu_rcs` (MI command codecs) |
| 2c  | Command Reference: Engines           | `intel_gpu_rcs` (execlists / LRC model) |
| 5   | Memory Views                         | `intel_gpu_gtt`, `intel_gpu_rcs` |
| 11  | Display Engine Registers             | `intel_gpu_pll`, `intel_gpu_dp` (HPD) |
| 12  | Display DDIs / Plane Programming     | `intel_gpu_ddi`, `intel_gpu_gmbus`, `intel_gpu_audio` |
| 14  | Display Engine                       | `intel_gpu_pipes`     |
| 16  | Workarounds                          | (consult per-bug)     |

Every register cited in a `intel_gpu_*` module names its source
volume + section in a doc-comment so a future maintainer can find
the canonical bit definition without re-deriving it.

## 4. Stage plan

### Stage 1 (landed) — PCI claim + presence test
- `intel_gpu.rs`: vendor `0x8086`, class `0x03`, exact match table
  (§5, Gen9 through Nova Lake-S plus the discrete lists),
  plus a class-match backstop that filters on vendor.
- BAR0 (GTTMMADR) maps the unified MMIO + GTT window. BAR2 maps
  the stolen-memory frame-buffer aperture on iGPUs.
- Presence test is generation-aware. Gen12+ reads `GMD_ID`
  (Graphics Media Device Identifier, MMIO 0xD8C) plus the
  `MTCFG_TRBLK` cookie (0xFF8); all-ones means the BAR is mapped
  but no silicon backs it. Pre-GMD Gen9 and Gen11 have no such
  registers, so their presence test
  re-reads PCI config space (vendor/device dword, offset 0);
  all-ones refuses, and `gmd_id` is `None`.
- Records `BoundDriver { name: "intel-gpu", kind: Graphics }` on
  successful probe.

### Stage 2 (landed) — Codec layer
- **`intel_gpu_gmbus`** — GMBUS register file (MMIO 0xC5100..),
  CMD/STATUS bit layout, GMBUS pin numbering with the per-PCH
  `get_gmbus_pin` tables (icp/dg1/dg2/mtp), E-EDID
  read transaction encoder, and the MMIO transport (`GmbusBus`):
  `xfer` over I2C message lists as `do_gmbus_xfer` (poll-counted
  HW_RDY / wait-phase waits between messages, one STOP-cycle +
  wait-idle teardown, SATOER NAK recovery with one first-message
  retry, CYCLE_INDEX|CYCLE_WAIT / GMBUS5 2BYTE_INDEX_EN indexed
  transfers) and the E-DDC EDID reader. Register map corrected against
  PRM Vol. 12 + i915 `intel_gmbus_regs.h` in #1018 (base
  0xC5100, GMBUS5 at +0x20, HW_WAIT_PHASE at GMBUS2[14]).
  Its disconnected Wa_16025573575 helpers exactly select display
  30.00/30.02/35.00 and form the GPIO mask pre-transfer, preserved-line and
  post-transfer images required by Linux 7.0-rc7. They do not add a GPIO
  bit-bash fallback, alter hardware GMBUS, or participate in Type-C DP AUX.
  Source: TGL PRM Vol. 12 "GMBUS Programming".
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
  the DDI ↔ transcoder route latch (`TRANS_DDI_FUNC_CTL`).
  Voltage-swing/pre-emphasis is NOT a `DDI_BUF_TRANS` table on
  Gen12 — it lives in `intel_gpu_gen12_combo_phy` (PORT_TX
  registers, per-family `.icl` tables).
  Source: TGL PRM Vol. 12 "Display DDI".
- **`intel_gpu_gtt`** — 64-bit GTT page-table entry layout: phys
  separate GGTT / PPGTT address, permission and PAT fields;
  Gen11 legacy Gen8 PPAT, Gen12 / Xe-LPG system-memory formats.
  Source: TGL PRM Vol. 5 "Memory Views".

Codec layer is transport-agnostic — it produces the wire
register values without performing the MMIO write. The
Stage-3 driver core consumes these codecs through the
`Transport`-equivalent indirection used elsewhere in narf
(direct MMIO in kernel mode, cap-mediated MMIO in userspace).

### Stage 3 (partially landed) — Display-only driver core
- Internal-panel takeover uses Pipe A / DDI A and reads EDID
  over AUX. External HDMI sessions use GMBUS (§15).
- Compute pipe / transcoder timing from an EDID detailed-timing
  block; program PIPE / TRANS / PLANE through the Stage-2 codec.
- Take over an enabled firmware Pipe A surface with link
  retraining. Arbitrary firmware pipe / DDI routing and a
  takeover preserving the trained link remain open.

### Stage 4 (partially landed) — Frame buffer + KMS
- GTT entry table population from the Stage-2 codec.
- PPGTT page-table walks per the PRM memory model — **landed**
  (§9).
- Single-rectangle scanout from a CPU-mapped buffer.

### Stage 5+ (partially landed) — 3D / compute
- Command streamer (RCS0) ring submission — **landed** as the
  execlists path in `intel_gpu_rcs` (§8), with GGTT batches and
  attached-context PPGTT batches (§18).
- PPGTT per-context page tables and media submission — **landed**
  (§9, §18).
- GuC submission, the Xe and i915 UAPI and the remaining work are
  in §19 and §20. Mesa interoperability is unproven.

## 5. PCI device ID table

The canonical table lives in code as `intel_gpu::DEVICE_TABLE`;
PCI registration and classification both derive from it, and the
`smoke_device_table_census` fixture pins the code table to this
section. Current Linux `include/drm/intel/pciids.h` is the primary family
census; six older ADL-P rows retained from the public `pci.ids` database
(4636/4638/463A/46B6/46B8/46BA) share the already-qualified ADL-P profile.
A row is added only when its existing platform profile already models that
register and GuC-firmware family.
The current census restores Tiger Lake 9A59/9AC0/9AC9/9AD9/9AF8 and
Alder Lake-P 46A2/46B2/46C2, which an older `pci.ids` extract had
incorrectly caused this driver to reject, and adds Rocket Lake only after
giving it its own exact pre-GMD platform profile.

Discrete identities are kept in their own exact lists rather than inserted
into the integrated `DEVICE_TABLE`: DG1 is 4905, 4906, 4907, 4908 and 4909;
DG2 and BMG retain their existing exact lists. ATS-M is 56C0/56C1/56C2 and
is registered as a PF-only display-less profile rather than aliased to
display-capable DG2. The same exact-match PCI registration and class backstop
rules apply.

| ASIC (`ChipInfo::asic`) | Device IDs |
| ----------------------- | ---------- |
| skylake (Gen9) | 1902, 1906, 190A, 190B, 190E, 1912, 1913, 1915, 1916, 1917, 191A, 191B, 191D, 191E, 1921, 1923, 1926, 1927, 192A, 192B, 192D, 1932, 193A, 193B, 193D |
| kabylake (Gen9) | 5902, 5906, 5908, 590A, 590B, 590E, 5912, 5913, 5915, 5916, 5917, 591A, 591B, 591C, 591D, 591E, 5921, 5923, 5926, 5927, 593B, 87C0 |
| coffeelake (Gen9) | 3E90, 3E91, 3E92, 3E93, 3E94, 3E96, 3E98, 3E99, 3E9A, 3E9B, 3E9C, 3EA5, 3EA6, 3EA7, 3EA8, 3EA9, 87CA |
| whiskeylake (Gen9) | 3EA0, 3EA1, 3EA2, 3EA3, 3EA4 |
| cometlake (Gen9) | 9B21, 9B41, 9BA2, 9BA4, 9BA5, 9BA8, 9BAA, 9BAC, 9BC2, 9BC4, 9BC5, 9BC6, 9BC8, 9BCA, 9BCC, 9BE6, 9BF6 |
| broxton (Gen9 LP) | 0A84, 1A84, 1A85, 5A84, 5A85 |
| geminilake (Gen9 LP) | 3184, 3185 |
| icelake (Gen11) | 8A50, 8A51, 8A52, 8A53, 8A54, 8A56, 8A57, 8A58, 8A59, 8A5A, 8A5B, 8A5C, 8A5D, 8A70, 8A71 |
| elkhartlake (Gen11) | 4541, 4551, 4555, 4557, 4570, 4571 |
| jasperlake (Gen11) | 4E51, 4E55, 4E57, 4E61, 4E71 |
| lunarlake (Xe2-LPG; display 20 opt-in) | 6420, 64A0, 64B0 |
| tigerlake (Gen12) | 9A40, 9A49, 9A59, 9A60, 9A68, 9A70, 9A78, 9AC0, 9AC9, 9AD9, 9AF8 |
| rocketlake (Gen12; internal display gated) | 4C80, 4C8A, 4C8B, 4C8C, 4C90, 4C9A |
| alderlake-p (Gen12) | 4626, 4628, 462A, 4636, 4638, 463A, 46A0, 46A1, 46A2, 46A3, 46A6, 46A8, 46AA, 46B0, 46B1, 46B2, 46B3, 46B6, 46B8, 46BA |
| raptorlake-p (Gen12) | A720, A7A0, A7A8, A7AA, A7AB |
| raptorlake-u (Gen12) | A721, A7A1, A7A9, A7AC, A7AD |
| alderlake-m (Gen12) | 46C0, 46C1, 46C2, 46C3 |
| alderlake-n (Gen12) | 46D0, 46D1, 46D2, 46D3, 46D4 |
| alderlake-s (Gen12) | 4680, 4682, 4688, 468A, 468B, 4690, 4692, 4693 |
| raptorlake-s (Gen12) | A780, A781, A782, A783, A788, A789, A78A, A78B |
| meteorlake (Xe-LPG) | 7D40, 7D45, 7D55, 7D60, 7DD5 |
| arrowlake (Xe-LPG) | 7D41, 7D51, 7D67, 7DD1, B640 |
| pantherlake (Xe3-LPG) | B080, B081, B082, B083, B084, B085, B086, B087, B08F, B090, B0A0, B0A1, B0B0 |
| wildcatlake (Xe3-LPG; display 30.02 opt-in) | FD80, FD81 |
| novalake-s (Xe3-LPG; display 35.00 opt-in) | D740, D741, D742, D743, D744, D745, D74A, D74B |

Linux `INTEL_ADLP_IDS` includes 46B0–46B3. The historical
`intel-gpu-rpl-46B*` registration names for these four devices remain
available for bus consumers. Raptor Lake-P and Raptor Lake-U have distinct
ASIC names and both use the Alder Lake-P GT and display profiles.

Rocket Lake is not a Tiger Lake device-ID alias. Linux
`include/drm/intel/pciids.h` supplies the exact six-ID census;
`drivers/gpu/drm/xe/xe_pci.c` gives it the pre-GMD Xe-LP, 39-bit-DMA,
three-level-VM integrated profile; and `xe_uc_fw.c` selects
`i915/tgl_guc_70.bin` at ABI 70.44.1 or newer. The separate
`Gen12Platform::RocketLake` identity preserves those GT facts. Linux display
data also gives RKL three pipes, the display-12 minimized plane set, and the
distinct A/B/TC1/TC2-to-combo-PHY A/B/C/D map. NARF admits RKL external DP,
HDMI and MST on combo DDI B, the port the external HPD monitor owns: there
PHY B's PLL (DPLL1, `RKL_DPLL_CFGCR*(1)`), its `DPCLKA_CFGCR0` field and its
DDC pin (`rkl_encoder_to_ddc_pin`) are Tiger Lake's, and the modeset takes
`rkl_cdclk_table` and the RKL power-well map (no PW_2; Pipe B under PW_3,
Pipe C under PW_4). Hotplug pairs RKL with TGP (ICP bank) or CMP/CMP2 (SPT
bank). TC1/TC2 (DDI D/E) are admitted too as the combo ports they are: PHY C/D
(`_RKL_COMBOPHY_D` 0x161000), Linux's {DPLL0, DPLL1, DPLL4} pool (a port
shares a PLL another port runs at its state, else takes its own or the first
unheld one, as held is read from `DPCLKA_CFGCR0`), RKL's DPCLKA layout, PW_3
for their lanes and AUX, hotplug on the TGP Type-C pins or the CMP port C/D
pins, and `rkl_encoder_to_ddc_pin`'s PCH-dependent DDC pins. The internal panel
stays unadmitted, so the internal display path preserves a firmware-lit
display; the display-less GuC owner starts beside it when every enabled
plane and cursor fetches below 192 MiB and no DSB runs (`planes_below_arena`).

DG1 is likewise not a DG2 alias. Linux `xe_pci.c` identifies it as discrete
Xe-LP+ graphics 12.10 with a 39-bit DMA mask and three-level VM, and
`xe_uc_fw.c` selects `i915/dg1_guc_70.bin` at ABI 70.44.1 or newer. The
dedicated `Gen12Platform::Dg1` preserves those facts and selects DG1's exact
64-entry MOCS/L3CC table (undefined rows copy WB-L3 index 5; the published UC,
fractional-cache and reserved rows remain literal). Before the Gen12 reset,
the discrete owner proves every enabled plane and cursor on the four pipes
fetches below 192 MiB and no DSB runs (`validate_discrete_display`); an
unreadable plane fails closed. DG1 has no flat CCS and no tile range register,
so its VRAM pool is the LMEM BAR from offset zero up to `GSMBASE`
(`xe_vram.c`), in 4 KiB pages CPU-cleared through the BAR. DG1 shares RKL's
display-12 port/AUX mapping and has its own DG1 GMBUS/default-pin metadata,
but no KMS route is admitted yet.

Gen11 (Ice Lake / Elkhart Lake / Jasper Lake) is the first
pre-Gen12 family admitted, identity + probe (Gen11 Lane 1) plus the
legacy Gen8 PTE format and exec wiring (Gen11 Lane 2): `PteFormat::Gen8`
encodes PPGTT leaves with the legacy PPAT levels
(`gt/gen8_ppgtt.c::gen8_pte_encode`, `gt/intel_gtt.h:135-138`) and the
exec layer selects it for `GtPlatform::Gen11` with leaf cache level
`I915_CACHE_LLC` and table policy `PPAT_CACHED_PDE` = 0, so GEM objects
are mappable on Gen11. The Gen11 GGTT has no PAT bits — same as Gen12:
Linux `gt/intel_ggtt.c` selects `mtl_ggtt_pte_encode` (PAT bits 53:52)
only at `GRAPHICS_VER_FULL >= IP_VER(12, 70)`; every earlier generation
uses `gen8_ggtt_pte_encode`, which ignores the PAT index.
Linux `include/drm/intel/pciids.h` supplies the exact 26-ID census
(`INTEL_ICL_IDS` 15, `INTEL_EHL_IDS` 6, `INTEL_JSL_IDS` 5); one
`Generation::IceLake` carries all three products (the
Raptor-Lake-under-AlderLake pattern) with `asic` per product, while
`GtPlatform::Gen11` keeps a sub-platform per product because the
GuC firmware family differs: Ice Lake takes
`i915/icl_guc_70.1.1.bin`, Elkhart/Jasper Lake take
`i915/ehl_guc_70.1.1.bin`, both at minimum 70.1.1
(`gt/uc/intel_uc_fw.c` `INTEL_GUC_FIRMWARE_DEFS`). Gen11 shares
the Gen12 BAR0/GTT partitioning (`intel_uncore.c::__gen11_fw_ranges`),
so its region table carries the verified Gen12 contents; it has a
39-bit DMA mask (`i915_pci.c` GEN11_FEATURES) and the Gen9 GT
forcewake ACK at 0x130044, and no HWCONFIG table (i915 requires
graphics 12.55+). Gen11 predates GMD_ID, so Stage 1 presence
re-reads PCI config space (all-ones refuses) instead of reading
0xD8C/0xFF8, and `gmd_id` is `None` on Gen11. Display clocks (Lane 4), the internal-panel modeset (Lane 5)
and the external outputs (Lane 8) are admitted: CDCLK (pcode
command 0x7, per-product voltage levels), the ICL combo DPLL
(CFGCR0 0x164000 + pll·0x80), the 8-level watermark algorithm
(no SAGV watermark), the ICL DDI tables, the DMC load
(`i915/icl_dmc_ver1_09.bin`, best-effort), and the first modeset
on the internal display — in Linux's ICL order (CDCLK → DPLL →
DDI pre-enable → transcoder/pipe/M-N/FUNC_CTL → DBUF +
watermarks → plane → link training → DDI buffer → enables),
fixture-validated, silicon untested. The plane admission is the
SKL rule: 256 KiB surface alignment, 32 KiB stride cap. Lane 8
adds the Gen11 port map (combo PHY A/B + TC1–TC4 MG, §12.3),
the MG PLL divisor search + TC-port programming, the TBT PLL
fixed rows, external DP on combo-PHY/TC ports, HDMI on combo
and TC ports, and the backlight PWM install (BXT-style block,
shared with Gen12 — §12.3). `external_display_supported()` and
`backlight_supported()` are flipped for Ice Lake, and the HPD /
external-session layer admits Gen11 through `SourceFamily::of` (§7).
Execlists submission (Lane 3) is admitted — a Gen11
batch executes on RCS with no GuC loaded — and GuC/HuC load
(Lane 7) is admitted: the GuC profiles are `i915/icl_guc_70.1.1.bin`
and `i915/ehl_guc_70.1.1.bin`, both at minimum 70.1.1, and the HuC
profiles are `i915/icl_huc_9.0.0.bin` and `i915/ehl_huc_9.0.0.bin`
(`gt/uc/intel_uc_fw.c` `INTEL_GUC_FIRMWARE_DEFS` /
`INTEL_HUC_FIRMWARE_DEFS`); the 9.0.0 is the HuC filename version,
not an enforced minimum, because Linux applies no version matching
to HuC. The WOPCM plan for Gen11 is the 2 MiB total
(`gt/intel_wopcm.c` `GEN11_WOPCM_SIZE`), with the 36 KiB ICL
hardware-context reservation at the top. GuC submission stays
optional on Gen11 by design (execlists is the submission path);
the GuC is loaded where a GuC owner exists, which is what HuC
authentication requires.

Gen9 (Skylake / Kaby Lake / Coffee Lake / Whiskey Lake / Comet Lake)
is admitted from identity + probe (Gen9 Lane 1) through the external
outputs (Lane 8, §12.7). Linux
`include/drm/intel/pciids.h` supplies the exact 86-ID census
(`INTEL_SKL_IDS` 25, `INTEL_KBL_IDS` 22, `INTEL_CFL_IDS` 17,
`INTEL_WHL_IDS` 5, `INTEL_CML_IDS` 17); every row was re-verified
against `pciids.h` (Linux 7.4-rc2) at authoring time — the audit's
carried census, now re-derived. One `Generation::Skylake` carries
all five products (the `Generation::IceLake`-carries-all-Gen11
pattern) with `asic` per product, while `GtPlatform::Gen9` keeps
a sub-platform per GuC firmware family — `Skylake`, `KabyLake`,
`CometLake` — because the firmware family differs: Skylake takes
`i915/skl_guc_70.1.1.bin`, Kaby Lake / Coffee Lake / Whiskey Lake
take `i915/kbl_guc_70.1.1.bin`, Comet Lake takes the KBL blob at
rev < 5 and `i915/cml_guc_70.1.1.bin` at rev >= 5
(`gt/uc/intel_uc_fw.c` `INTEL_GUC_FIRMWARE_DEFS`), all at minimum
70.1.1. The GuC profiles are admitted in Lane 1 because the
device-table census fixture requires a qualified GT/GuC profile
for every census DID; GuC submission stays optional on Gen9
(execlists is the submission path). GuC/HuC load is admitted (Lane 7):
the HuC profiles are `i915/skl_huc_2.0.0.bin` and
`i915/kbl_huc_4.0.0.bin` (`gt/uc/intel_uc_fw.c`
`INTEL_HUC_FIRMWARE_DEFS`); the 2.0.0/4.0.0 is the HuC filename version,
not an enforced minimum, because Linux applies no version matching
to HuC. The 256-byte GuC signature goes through the scratch registers
on Gen9 exactly as on Gen11/Gen12 (Linux `guc_xfer_rsa` selects on
size, with no generation gate), and the Gen9-only `guc_prepare_xfer`
writes (DOP clock gating, 5 us RC6 hold) run ahead of the DMA upload.
The CML rev>=5 split follows the PCI revision ID, which the GT runtime's
`validate_pci` already reads at config offset 0x08: `GtPlatform::
guc_for_revision` and `intel_gpu_huc::firmware_name_for_revision` take
the `cml_*` blobs at revision 5 and above, as `__uc_fw_auto_select`
takes the first `INTEL_REVID` row the device reaches. The revision stays
out of `GtPlatform` itself, because GT, render and scheduler objects
compare their platforms for equality. Gen9 shares the Gen12 BAR0/GTT partitioning
(Gen8+ 16 MiB split), so its region table carries the verified
Gen12 contents; it has a 39-bit DMA mask (`i915_pci.c`
GEN9_FEATURES `.dma_mask_size = 39`) and the Gen9 GT forcewake
ACK at 0x130044, and no HWCONFIG table (i915 requires graphics
12.55+). Gen9 predates GMD_ID, so Stage 1 presence re-reads PCI
config space (all-ones refuses) instead of reading 0xD8C/0xFF8,
and `gmd_id` is `None` on Gen9. The WOPCM plan for Gen9 is the
1 MiB total (`gt/intel_wopcm.c` `GEN9_WOPCM_SIZE`). The internal
display modesets (Lane 5, §12.6); external display and backlight are
admitted (Lane 8, §12.7). Execlists submission is admitted (Lane 3), with the
Gen9 media-engine table. Lane 4 admitted the display model:
SKL CDCLK via LCPLL (`intel_gpu_gen9_cdclk.rs`, VCO-aware ladders,
Wa Display #1183), the SKL WRPLL + CFGCR1/2
(`intel_gpu_gen9_dpll.rs`), the Gen9 watermarks
(`intel_gpu_gen9_wm.rs`: 8 levels, 892-block single-slice DBUF, no
transition watermarks) and the `DDI_BUF_TRANS` swing tables
(`intel_gpu_gen9_ddi.rs`, 106 entries) + the SPT GMBUS pin table
(`intel_gpu_gmbus.rs`: SPT pins 4/5/6 = DPC/DPB/DPD). Gen9 has no VRR (Linux `HAS_VRR`
needs DISPLAY_VER >= 11). The §6 lift for Gen9 display is Lane 0's.

Gen9 LP (Broxton / Gemini Lake): the 7 IDs (BXT
0A84/1A84/1A85/5A84/5A85, GLK 3184/3185) are `Generation::Broxton`. The
execlists owner runs them as `LegacyGt::Gen9Lp` (CHV snooping PPAT, Broxton
MOCS, the LP workarounds, one slice of three subslices with pooled EUs, the
19.2 MHz crystal, `BXT_RP_STATE_CAP`, RC6 behind `bxt_check_bios_rc6_setup`).
The display runs the Skylake modeset with the LP blocks in place
(`Modeset::gen9_lp`): the DPIO PHY (`intel_gpu_bxt_phy`), per-port PLLs
(`intel_gpu_bxt_dpll`), the DE-PLL CDCLK (`intel_gpu_bxt_cdclk`), the
512−4 / 1024−4 DBUF (Linux `display/intel_display_device.c:848,863`), Gemini
Lake's display-10 watermarks, the PPS at `PPS_BASE`, and DP/HDMI on DDI B/C
with the display-engine hotplug bank (`HpdBank::Bxt`, its sense inversion
from the VBT's `hpd_invert`). The backlight runs on the VBT panel's PWM
controller (`BXT_BLC_PWM_*(controller)`). HDMI refuses the DPLL ranges Gen9
LP cannot generate; Gemini Lake reaches 594 MHz scrambled and runs YCbCr
4:2:0 through the pipe CSC with a linear degamma (display 10 has no output
CSC). A GOP framebuffer stays fixed-mode KMS when no modeset runs. Not run on
silicon.

EHL/JSL 36-bit PPGTT: Linux `i915_pci.c` sets
`.__runtime.ppgtt_size = 36` for Elkhart Lake and Jasper Lake only;
Ice Lake inherits the Gen8 default 48. The walk stays four-level on
all three (`gen8_ppgtt.c`: `ppgtt->vm.top = i915_vm_is_4lvl(...) ? 3 : 2`,
and `(2^36 - 1) >> 32` is nonzero, so `i915_vm_is_4lvl` is true), so
NARF's root level 3 is correct as-is — only the VA ceiling differs
(2^36 vs 2^48). `GtPlatform::ppgtt_va_size` carries that total: the
i915 `CONTEXT_PARAM_GTT_SIZE` reports it, and exec preparation bounds
every softpinned object and the batch by it.

Wildcat Lake IDs FD80/FD81 are exact `INTEL_WCL_IDS`. Linux deliberately binds
them to the same `ptl_desc` as Panther Lake and selects the PTL GuC profile.
`ChipInfo` retains broad `Generation::PantherLake` display gating and
`asic: "wildcatlake"`, while GT policy uses the distinct
`GtPlatform::WildcatLake`. The headless owner admits only live graphics
30.03/30.04/30.05 and media 30.02, applies the source Xe3 policy without PTL's
graphics-30.00 A0 workaround, and skips the media-30.00-only GGTT dummy-write
workaround. `DisplayIp::WildcatLake` retains display 30's timing-generator,
PM-demand, watermark and CDCLK rules for exact resource admission, with only
Pipes/FBC A–C, the 480 MHz maximum and `xe3lpd_3002_sa_info`'s 22 GB/s
programmed-bandwidth limit. Resource images and idle proofs never touch Pipe
D. `ExternalDisplayProfile::WILDCAT_LAKE` likewise admits only TC1/TC2 and
scans only Pipes B/C, so sharing Panther Lake's graphics generation cannot
silently grant TC3/TC4 or Pipe D authority. The production KMS and hotplug
owners retain that exact profile, and native fixtures exercise C20
enable/training/fixed-TG/stop on TC1/TC2 and Pipes B/C.
`DisplayIp::decode_all` and the display-30 modeset accept 30.02,
but `display_route` binds it only to exact `GtPlatform::WildcatLake` plus the
distinct `narf.intel.wcl_display=1` request. Crossed PTL/WCL identities refuse
read-only. The production probe selects that route only for the distinct WCL
option and carries 30.02 through KMS install, resource capture, recovery and
the hotplug actor. Linux keeps WCL on the Panther Lake C20 path; it does not
select LT PHY.

`intel_gpu_lt_phy` separately models Nova Lake's A/B/TC1/TC2 LT-PHY boundary:
the seven source DP PLL images from RBR through UHBR20, their exact committed
VDR write image, the complete nine-rate eDP table, LT transmitter
ownership/masking, and distinct DP 1.4/UHBR/eDP signal tables.
`MmioWindow::has_lt_phy()` preserves Linux's exact
`HAS_LT_PHY(display) == platform.novalake` boundary instead of inferring the
PHY from display version. Its transport (`LtPhy`) serializes
the 81 committed PLL writes through the display-35 Cx0 bus and implements Linux's three-attempt
P2P transmitter flow, including ordinary ACK validation, bus reset on failure,
the 150 us settle bound and P2P-ready clearing. The same transport applies the
selected DP 1.4 or UHBR table with committed per-lane LT `TXY_CTL{8,2,3,4}`
RMWs. The DP enable/disable machine adds LT lane reset, P2/P0 power
transitions, display-35 clock selection, rate-update calibration and DDI
clock-value programming in Linux source order.
The eDP selector adds the five intermediate 216/243/324/432/675
MHz images to the four shared 162/270/540/810 MHz DP images. Each preserves the
source VDR config bytes and all thirteen PLL registers. The HDMI table selector
likewise preserves the five literal
25.2/27.2/74.25/148.5/594 MHz images. Every other clock uses a source-order,
bounded Q32 DCO/divider search that emits all thirteen PLL registers or refuses
the clock; table hits retain priority. The HDMI TMDS transport
applies those images through the shared lane-reset/P2/P0/rate-update sequence,
requires four non-DP-alt transmitters, excludes FRL, and uses DP1.4 entry zero
by default (or a valid VBT level) exactly as Linux does.
The separate ten-entry eDP signal table preserves its lower
main-cursor values and is written through the per-lane
`TXY_CTL{8,2,3,4}` writer rather than reusing external DP 1.4 levels.
The CDCLK table (`intel_gpu_xelpg_cdclk::NOVA_LAKE_TABLE`) pins all 31
`xe3p_lpd_cdclk_table` rungs from
151.2 through 787.2 MHz, including the ratio-21 squash waveforms, the 19.2 MHz
crawl ladder, display-30-style MDCLK source and zero-voltage-level hook. On Nova Lake-S,
`narf.intel.nvl_display=1` reports the firmware primary at PCI probe and skips
the headless GT reset for that boot, including when readout fails. For an
enabled SST output on port A it checks two live scanout snapshots and reports
the format, dimensions, byte pitch and GGTT offset. A primary that is the boot
framebuffer becomes fixed-mode KMS beside the display-preserving GT
(`DisplayOwner::NovaLake`, `admit_display_nvl`: no driver FLR, GT-only GuC and
full reset); any other primary is only reported. Firmware keeps the panel
unless `narf.intel.nvl_modeset=1` is also given: then, before the GT starts,
the probe runs the display-14 orchestrator on `DisplayIp::NovaLakeS` at the
panel's EDID mode on the unchanged firmware surface, with the port PLL,
transmitters and signal levels on the LT PHY (eDP tables) and the display-35
CDCLK, DBUF, watermark and bandwidth owners. It requires a VBT naming port A
eDP, no CMTG on transcoder A, an XR24 primary and a preferred mode of the
primary's size; each refusal precedes every write outside AUX and keeps the
firmware fixed-mode route, which still refuses system suspend. A successful
takeover continues on the integrated display path as display 30 does: Pipe A
claimed, the console moved to an owned GGTT surface (Xe2 PTEs at the firmware
surface's PAT0) and the display-35 KMS owner (`Display30` with
`DisplayIp::NovaLakeS`, PHY/AUX through `intel_gpu_xe3plpd::View`) beside the
display-preserving GT (`DisplayOwner::NovaLakeOwned`, `admit_display_nvl`).
That owned case admits system suspend: the KMS quiesce turns the panel's crtc
off after restoring the console (`drm_atomic_helper_suspend`), and resume
relights it through `intel_gpu_xe3plpd::relight` (`pps_init_registers` with the
probe's sequencer delays, then the cold panel-on through the LT PHY), refused
without the panel-off record. A refused console handoff keeps the firmware
surface as fixed-mode KMS with the firmware route's GT owner. Beside the owned
panel, the display-14 external route drives LT port B (DP 1.4 and HDMI TMDS on
Pipes B-D) and TC1/TC2 (DP-alt, declared legacy HDMI) over the same view: PLL
enable/disable and signal levels on the LT PHY (`ExternalDisplayProfile::
admits_port` opens B/TC1/TC2 for `NovaLakeS`, and `admits_view` refuses a
profile whose PHY family the view does not report). UHBR, Thunderbolt alt
mode (`ExternalError::LtTbtAlt`) and HDMI FRL stay refused.
WCL uses its separate C10/C20 route.
`intel_gpu_nvl_resources` is a separate, pure ownership model; the owned
route above does not use it. It admits only eDP on LT port A/Pipe A, native DP or HDMI TMDS on LT
port B/Pipes B-D, and DP-alt on LT TC1/TC2/Pipes B-D. Each plan retains the
same-index transcoder and HPD source; DC-off, PW1 and the pipe well; PW2 for
Pipes C/D or either Type-C lane domain; and the D2D requirement. DP/eDP plans
retain the exact AUX control register and LT-only request/status handshake,
while native HDMI retains no AUX lease and requires a VBT-qualified GMBUS/DDC
route. TC1/TC2 plans additionally
retain PICA_TC and the TCSS PHY index. Crossed port/connector roles and an
external Pipe A refuse before MMIO.
The shared Xe-LPDP AUX power owner branches only on the exact
`MmioWindow::has_lt_phy()` platform fact. Nova LT windows raise the same
per-channel request bit but require `POWER_STATUS` within 2 ms and require it
to clear within 1 ms on release; timeout, lost access and an in-flight AUX
transaction are distinct typed failures. C10/C20 windows retain their existing
600-us enable and 10-us disable delays.
Panther and Wildcat Lake Type-C power transitions run Wa_14020908590 before
changing `XELPDP_TCSS_POWER_REQUEST`: wait up to 10 ms for the TCSS display
mailbox to become idle, write enable/disable data, issue command 1 with
RUN_BUSY, and wait another 10 ms for completion. The exact display-30 MMIO
view selects the workaround; Meteor/Lunar and Nova do not inherit it. A busy
mailbox is a typed refusal instead of continuing through the documented
request/ack hazard.
The shared Type-C owner retains `TcDisplayProfile` instead of a broad
`display20` boolean: Xe-LPDP 14.00, Xe2-LPD 20.00, Xe3-LPD 30.00, Wildcat
30.02 and Nova 35.00 are distinct values. The profile selects PICA, TCSS pin
assignment and the Display-30 mailbox workaround, and it must agree with the
MMIO view's exact `cx0_xe3`/`has_lt_phy` facts before any Type-C access. Nova
therefore exercises PICA/TCSS ownership without inheriting the Display-30
mailbox; Meteor retains FIA pin assignment and no PICA.
`NovaResourcePlan::{enable_d2d,disable_d2d}` realizes the plan's D2D
dependency through Display >=20's `DDI_BUF_CTL` bits 29/28 and the source
100-us state bounds. The shared low-level helper is separated from
operational `DisplayIp`, but Nova requires `has_lt_phy()` before its first
register access. Missing state is typed and a crossed non-LT view writes
nothing.
`NovaResourcePlan::acquire_main_wells` requests PW1, optional PW2 and the
selected PW_A--D in dependency order, waits up to 1 ms for each state and
fuse-distribution indication (failing closed where Linux only warns), and
records only DRIVER requests absent on entry. The same token retains partial
grants for reverse-order release and never clears pre-existing DRIVER
requests. BIOS, KVMR or
debug requests may keep a released well raised, matching Linux's forced-on
rule. The exact LT-PHY platform fact is checked before the first register read.
`NovaPortLease` prepares a dark DDI with the caller holding DC-off and
serializing access to the port and PICA. It acquires main wells, then PICA and
TCSS ownership for live native DP-alt on TC1/TC2, then LT AUX for DP/eDP.
Combo ports A and B use the PICA bases `0x16fa00` and `0x16fc00` for
AUX and PHY, including BUF_CTL5 and P2P responses. The shared mapping
preserves the separate DDI control and clock value/frequency addresses.
The Type-C connection retains the negotiated pin assignment and lane ceiling
for the LT PHY. Existing PICA, TCSS and AUX ownership, a live DDI, and
fabric-only USB4/TBT HPD cause refusal.
Following the i915 `intel_ddi_pre_pll_enable` and
`mtl_ddi_prepare_link_retrain` phases, D2D is requested separately after PLL
setup. D2D release requires the DDI enable bit clear and PHY idle observed.
After retiring the PLL, the caller releases AUX, Type-C ownership, TCSS,
PICA, and the main wells. Failed preparation attempts reverse-order cleanup.
An unconfirmed release returns the failing step and leaves the outstanding
requests with the same lease for retry.
Display 35's watermarks force the reported level-0 latency
to zero before the 6-us WaWmMemoryReadLatency adjustment and selects method 2
for every linear plane; unpanned Tile4 retains the display-30 calculation.
Its MDCLK image uses the Xe3P MBUS throttle field at bits 16:13
and the five-bit DBUF minimum tracker at bits 20:16. The lowest clock's ratio
is 6 and becomes 12 when MBUS is joined, which would be truncated by the
display-20 field.

`intel_gpu_nvl_dbuf::NovaDbufPlan` computes a complete set of primary and
cursor allocations for unscaled XR24 scanout on the available Pipes A through
D. Each pipe supplies its VRR guardband. The plan takes the maximum of the
caller, pixel-rate and DBUF bandwidth clock floors and selects the first Nova
CDCLK rung that meets it. A single Pipe A or B joins both MBUS banks. When
pipes share a bank, the allocator splits it by active width and reserves the
cursor at the end of each pipe's range. A hidden cursor retains its allocation.
The plan produces the full-modeset MBUS, slice request/tracker, active DBOX,
and plane/cursor watermark and DDB images. It is the fixture oracle for the
live display-35 resource transaction, which computes its own images.
Display 35's disconnected FBC helpers preserve the source format boundary:
the Lunar five-format set, four 64-bit integer formats, and only ARGB/ABGR
FP16. Only the FP16 pair receives `PLANE_PIXEL_NORMALIZE_ENABLE` with the 1.0
factor on HDR planes 1--3. The 2 MiB system-cache image uses the stolen offset
in 4 KiB units and the range in 64 KiB units, with cache reads disabled for
Wa_14025769978. The live FBC owner and production Nova route do not call these
helpers.
`intel_gpu_xe3plpd` also types the display-35 deltas that must not fall
through display 30: no `TRANS_VSYNCSHIFT` write or transcoder interlace bits,
interlace readback always false, linear/X reflection admitted with Tile4
reflection refused, and semiplanar YUV aligned vertically by two (both axes
when rotated). The live transcoder path skips `TRANS_VSYNCSHIFT` itself
(`intel_gpu_xelpg_pipes`); KMS does not call these typed plans. The module
also decodes each pipe's four six-plane
`UNDERRUN_DBG1` reasons, frozen 11-bit frame/20-bit line counters, optional FBC
decompression starvation and the package-C-state memory-blocking latch. It
returns Linux's exact write-one-to-clear images (full nonzero DBG1; only the
frozen/FBC/package bits for the other registers), but no IRQ or MMIO caller is
installed.
Display 35's core capability plan installs no shared DPLL manager because each
PLL belongs to its LT PHY, performs no legacy PCH reset handshake, and does not
read gamma/CSC enable state from `SKL_BOTTOM_COLOR` (while retaining the
separate commit-arm register contract). Its plane-color pipeline exposes a
17x17x17 tetrahedrally interpolated, bypassable 3D LUT only for primary planes
on Pipes A/B. These are disconnected admission facts, not color UAPI or MMIO.
The same module decodes Display 35's `MTL_MEM_SS_INFO_GLOBAL` and retains the
source 65 GB/s `xe3lpd_sa_info` ceiling. `XE3P_ECC_IMPACTING_DE` is a typed
refusal because Linux 7.0-rc7 states that Bspec supplies no handling rule;
there is no guessed derating, and the live bandwidth read
(`intel_gpu_xelpg_bw`) refuses it the same way.
The DMC parser separately tags Panther (`xe3lpd_dmc.bin`), Wildcat
(`xe3lpd_3002_dmc.bin`) and Nova (`xe3p_lpd_dmc.bin`) under their shared
0x8000 ceiling. Panther/Wildcat KMS passes its retained exact identity and
read-flush fact to the DC service, which restores Pipe C/D DMC MMIO and uses
the display >= 20 flip-queue/interrupt brackets; a broad generation cannot
select either container. Nova's owned route (`narf.intel.nvl_display=1` with
`narf.intel.nvl_modeset=1`) passes display 35.00 the same way: its service
loads `xe3p_lpd_dmc.bin` under the same Pipe C/D rule, writes `DC_COUNT_EN`
after each load, arms the display-35 pipe-DMC interrupts
(`PIPEDMC_FLIPQ_PROG_DONE | PIPEDMC_ERROR`), takes Linux 7.4-rc4's
`gen9_dc_mask` and CMTG read-only mask for `DC_STATE_EN`, and targets DC6
(DC3CO, which needs the CMTG, is never armed). Every display-35 AUX transfer
and LT PHY message-bus transaction takes its own DC_off reference
(`xe3plpd_pwdoms_dc_off`, `intel_lt_phy_transaction_begin`).

The Nova Lake-S census includes the exact `INTEL_NVLS_IDS` from Linux 7.4-rc1
and retains D744 from Linux 7.0-rc7. Linux gives them a
distinct integrated descriptor (DMA46, flat CCS, 48-bit VA, root4), the Xe2
MOCS table and display/media 35.00. Firmware packages supply
`xe/nvl_guc_70.bin`. If that name is absent, the loader tries
`xe/nvl_guc_70.55.4.bin` from Linux 7.0-rc7's `xe_uc_fw.c`. Both images
must meet the 70.55.4 minimum. `GtPlatform::NovaLakeS` admits the
source graphics-GMD set 30.03/30.04/30.05 plus media 35.00 on the driver-FLR
headless route unless `narf.intel.nvl_display=1` selects the
display-preserving route above.

Nova Lake-P IDs D750 through D757 and D75F use their own Xe descriptor.
The driver registers these nine IDs and reports the product before PCI
setup. Linux 7.4-rc1 has no NVL-P GuC firmware entry.

Crescent Island IDs 674C through 6750 use exact PCI-device registration
from Linux 7.4-rc1 `INTEL_CRI_IDS`. Linux describes its
discrete DMA52, VA57, root4, non-flat-CCS Xe3p_XPC profile, but the current
`xe_uc_fw.c` manifest has no `CRESCENTISLAND` GuC entry. NARF therefore
announces the exact identity and refuses before D-state, BAR, command or MMIO
effects. It is not aliased to NVL-S firmware or BMG memory policy.

Arctic Sound-M IDs 56C0/56C2 (M150) and 56C1 (M75) are exact
`INTEL_ATS_M_IDS`. Linux describes them as display-less DG2-platform
accelerators: pre-GMD graphics/media 12.55, DMA46, flat CCS, 48-bit VA/root3,
64 KiB VRAM granularity, SR-IOV, and `i915/dg2_guc_70.bin` 70.53.0 or newer.
NARF's current `Alchemist` owner also implies display-capable DG2 policy and
device-specific lifecycle policy, so ATS-M is not silently inserted there.
`GtPlatform::ArcticSoundM` now types its pre-GMD 12.55 identity, DMA46/root3,
DG2 GuC/cache/topology mechanics and exact M150=G10 / M75=G11 workaround
subplatform. Its source `has_display=false` descriptor is a separate typed
fact: validation never inventories display planes and discrete probe never
reads display identity for ATS-M. Linux assigns the descriptor `PLATFORM(DG2)`,
so NARF's `is_dg2()` architecture predicate now selects the shared MCR
steering, GT/LRC workarounds, context and reset images, Gen12 PTE/PAT rules,
64-KiB VRAM mapping, Flat-CCS copy/clear, SLPC, GuC log/stream and non-privilege
policies for ATS-M as well as display-capable DG2. Trusted CCS-clear batches
retain the actual platform identity instead of being mislabeled Alchemist.
Display, fan and SR-IOV policy remains separate.

The exact IDs now bind the display-less physical-function owner. NARF does not
implement an ATS-M VF lifecycle: initial PCI admission and every later GT/GGTT
access require SR-IOV `VF Enable == 0`, `NumVFs == 0`, and the MMIO `VF_CAP`
PF bit clear, along with current PCI identity, BAR0, command and D0. The
authorized window bootstraps with the VF-capability read but does not apply the
integrated four-zero workaround. GGTT PTE writes retain that same window, so an
external VF enablement revokes execution instead of leaving an independently
DMA-capable VF outside the client gate. The PF uses the existing isolated DG2
GT reset path; no function-level reset or display transaction is performed.

ATS-M and retail DG2 share the source package-temperature, VRAM-temperature,
voltage, energy and non-mailbox package-power register policy. They do not
share fan capability: Linux sets `has_fan_control` only on the retail `dg2_desc`
and omits it from `ats_m_desc`. `GtPlatform::has_fan_control()` preserves that
descriptor fact; ATS-M publishes no fan attributes and its telemetry service
performs no fan-counter reads. Battlemage and retail DG2 retain their existing
fan services.

SR-IOV capability is also kept as a source descriptor fact rather than inferred
from architecture. `GtPlatform::has_sriov()` is true for Tiger Lake,
Alder/Raptor Lake P/S/N, ATS-M, Battlemage, Panther Lake and Wildcat Lake, and
false for Rocket Lake, DG1, Meteor/Arrow Lake, Lunar Lake, retail DG2 and Nova
Lake-S. NARF implements no VF lifecycle on any of them. Every capable PF uses
the same bounded extended-capability proof and MMIO `VF_CAP` role check for
each GT register and GGTT PTE access; an enabled or externally created VF
therefore revokes execution on all source-capable families, not only ATS-M.
The integrated Xe2/Xe3 takeover keeps its separately required four-zero
bootstrap ordering, while other capable PFs bootstrap only the `VF_CAP` read.

PCI DMA width is independent of PTE address capacity. The exact Linux xe
descriptor matrix is enforced at every qualified GGTT/PPGTT publication:
Gen12 and DG1 are DMA39; MTL/Arrow, DG2/ATS-M, BMG, LNL, PTL/WCL and NVL-S
are DMA46. This corrects the former DG2, MTL and BMG fall-through to 52 bits.
BMG separately follows its source graphics-20 descriptor: `vm_max_level = 4`
selects a five-level walk, and its 32-entry Xe2 PAT uses the Xe2 PPGTT leaf
encoding even though current system-memory WB leaves remain PAT2. DG2/ATS-M
retain the three-level root and Gen12 leaf format; MTL retains Xe-LPG.

Arrow Lake (#1023): the five IDs classify
`Generation::MeteorLake` under `asic: "arrowlake"` — the table
follows the silicon, not the product name. Arrow Lake's GT is
Xe-LPG and its display is Xe-LPD, and both Linux drivers bind
the IDs to the Meteor Lake platform: i915
`INTEL_ARL_IDS(INTEL_VGA_DEVICE, &mtl_info)` (`i915_pci.c`),
xe `INTEL_ARL_IDS(..., &mtl_desc)` (`xe_pci.c`), and display
`INTEL_ARL_IDS(INTEL_DISPLAY_DEVICE, &mtl_desc)`
(`intel_display_device.c`), with Arrow Lake distinguished
only as a subplatform (ARL-H = 7D51/7DD1, ARL-U = 7D41,
ARL-S = 7D67/B640 in `include/drm/intel/pciids.h`, torvalds/linux
master @ d135ab453a74). This is the Raptor-Lake-under-AlderLake
pattern one generation up. B640 is in the i915 ID macros and
current pci.ids ("Arrow Lake-H") but was absent from the
pci.ids v2.2 extract lane 1 worked from, so it arrives with
this lane; pci.ids and i915 disagree on B640's segment letter
(H vs the S macro), never on the family. The
`smoke_arrowlake_classification` fixture pins the set, the
generation, and the no-bleed boundary against the sibling
Meteor Lake IDs in the shared 0x7Dxx space.

A single class-match backstop (`MatchKind::Class { class: 0x03,
mask: 0xFF }`) catches every PCI VGA controller; the probe body
filters on `vendor == 0x8086` so AMD / NVIDIA / virtio-gpu cards
fall through to their own drivers. An Intel DID outside the
table is announced on the console as an unsupported ASIC and the
probe returns `NotForThisDriver` — it no longer collapses
silently into the same `BadDevice` used for dead hardware.

Internal display programming admits qualified Gen12 (Tiger Lake / Alder Lake /
Raptor Lake), Gen11, Gen9 and Gen9 LP, and the separate Meteor/Arrow Lake
Xe-LPG sequence. Rocket Lake
has an exact GT and VBT metadata profile; its external outputs on DDI B and
TC1/TC2 are admitted, and its internal display-programming gate stays closed.
Arrow Lake shares the `MeteorLake` classification and Linux's `mtl_desc`
display descriptor. Lunar, Panther and Wildcat Lake and Nova Lake-S keep
their headless execution profile unless their per-device route is requested
and admitted (`narf.intel.lnl_display=1`, `narf.intel.ptl_display=1`,
`narf.intel.wcl_display=1`, `narf.intel.nvl_display=1`; §17 and above); the
generation-level gates still refuse them. External sessions and PWM retain
their separate generation gates below.

## 6. Out of scope

- Power/thermal-firmware blob (PUNIT) — opaque, loaded by the
  platform.
- DP MST HDCP. HDCP 1.4 and 2.2 on external SST DP and HDMI run
  behind `narf.intel.hdcp=1` (§20, "HDCP 1.4 and 2.2").

## 7. Lane 1 (#1010) — display correctness core + publication

Landed on top of the Stage-3 modeset orchestrator (Gen12,
DDI A / eDP, single pipe):

- **Routing** — `TRANS_DDI_FUNC_CTL` (transcoder → DDI bind,
  DP-SST, 8 bpc, port width) and `DPCLKA_CFGCR0` (DPLL0 → DDI,
  two-write select-then-enable at the Gen12 address 0x164280)
  are programmed by the modeset. Neither was written before.
- **DP M/N** — `PIPE_DATA_M1/N1` + `PIPE_LINK_M1/N1` computed
  per TGL PRM Vol. 12 §"Transcoder MN Values" (uncompressed
  SST, N = 2^23, M rounded up; LINK_N written last as the
  hardware update trigger).
- **CDCLK floor** — CDCLK is raised (never lowered) to the
  smallest `icl_cdclk_table` rung satisfying the PRM rule
  `pixel rate <= 2 * CDCLK` (DE PLL ratio + CD2X divider
  select, pipe none, pcode frequency-request notifies around
  the change).
- **Watermarks / DBUF allocation** — lane 1 programmed the
  PRM's "Display Buffer Allocation and Watermark Programming
  Prior to OS Boot" basics (160 DBUF blocks, one level). Lane
  Q6 (#1024) replaced that with the full latency-based
  algorithm — see the Q6 note below; the pre-boot programming
  remains as the fallback when the pcode latency read fails.
- **Combo-PHY signal levels** — Gen12 combo ports never use
  `DDI_BUF_TRANS` (`has_buf_trans_select` is DISPLAY_VER < 10);
  the modeset programs the PHY through PORT_TX_DW2/DW4/DW5/DW7
  + PORT_PCS_DW1 + PORT_CL_DW5/DW10 from the per-family `.icl`
  tables (`intel_gpu_gen12_combo_phy`), prepared at (0, 0)
  before training and updated per-iteration from the sink's
  level requests via the `TrainingAux` callback. The old
  4-entry `DDI_BUF_TRANS` tables in `intel_gpu_ddi` are
  deleted. The eDP HOBL / low-vswing VBT bits are plumbed:
  probe installs the built-in panel's bits
  (`VbtEdpSignal::from_vbt`, BDB_LFP_POWER `hobl` at block
  offset 54, BDB 232+, and the EDP block's `low_vswing` nibble,
  BDB 173+), `modeset_display_family` hands them to the
  modeset, and the combo PHY selects the HOBL / low-vswing
  eDP tables (`tgl_get_combo_buf_trans_edp`) with the CL_DW10
  override on HOBL. Remainder: Linux retries without HOBL
  after a training failure with HOBL active (`hobl_failed`);
  NARF has no such retry yet. The same callback retunes the
  DPLL mid-training when the fallback ladder opens a retry
  attempt at a lower rate (pattern 1 after a dirty Configure):
  the DDI buffer and `DP_TP_CTL` stop, the DPLL is disabled
  and brought back up from the `combo_coeffs` row for the new
  rate, and the PHY is re-prepared — the combo equivalent of
  the Type-C `start_training(retune)` restart, minus the clock
  re-route (DPCLKA routing selects the DPLL index, which a
  rate change does not alter). M/N needs no mid-training step:
  the transcoder is not enabled until after training, and the
  modeset already reprograms M/N to the trained configuration
  on every path before the DDI buffer enables.
  The Tiger Lake UY (GT2) flag rides the same path on
  every port: `Modeset` derives it from the window's PCI
  device ID (`MmioWindow::tgl_uy`, the panel path re-asserts
  it from `ChipInfo`), so external DP, HDMI, and the MST
  primary stream select the UY HBR2 table above 270 MHz on UY
  parts — Linux `tgl_get_combo_buf_trans_dp`
  (`display->platform.tigerlake_uy`). HDMI is the exception
  Linux itself makes: it always takes the shared ICL HDMI
  table, UY or not.
- **PLL table corrected** — DPLL_CFGCR0/1 field layouts and the
  four DP coefficient rows now match TGL PRM Vol. 12's
  "DisplayPort Mode PLL Values" for the 19.2/38.4 MHz reference
  family (DCO 8100 MHz for all rates; P/K per rate). The 24 MHz
  family shares the dividers with int 0x151 / frac 0x4000;
  lane Q6 (#1024) implemented the DSSM reference-frequency
  selection between the families — see the Q6 note below.
- **PLANE_CTL format pinned** — source-format discriminants
  corrected to the ICL+ 5-bit field values (XRGB_8888 =
  0b01000); fixture-pinned against PRM Vol. 14.
- **Publication** — a probed Gen12 scanout is published to the
  framebuffer console through the same ACTIVE + observer
  protocol the AMD display pipeline uses, and the DRM card
  carries real KMS mode state (CRTC 1, encoder 2 TMDS,
  connector 3 eDP) instead of the identity stub.

Scanout handoff requires an enabled firmware Pipe A and a successful
takeover mode. Panel power with no admitted mode allocates no internal
surface and publishes no synthetic 1024×768 display. The owned scanout
becomes active only after its primary-plane register program is armed.

Takeover and relight share generation dispatch (Gen12 versus Xe-LPG),
with Lunar Lake and Panther Lake refused before MMIO (an admitted Lunar
or Panther Lake display takes its own display-20 or display-30 entry
instead, §17). Restore uses `modeset_fixed` on
the selected orchestrator, preserving the saved timing used to size the
new allocation even if EDID now advertises a different preferred mode.
Plane geometry, pitch and the complete 32-bit GGTT surface extent are
validated before pipeline teardown. This does not enable Xe-LPG PM or
establish physical display/suspend acceptance.
The external-session gate is separate: Xe-LPG and later displays never
enter this session layer; they run their own external route (§20, "MTL
external outputs"). Gen12, Gen11 and Gen9 sources arm combo HPD, DP SST (with the
display 9-11 stop order), HDMI and MST through `SourceFamily::of`; the
USB-C DP Alt Mode bridge drives Gen12 Dekel and Ice Lake MG ports.
Unsupported generations return before HPD
register access; enabling the Xe-LPG internal panel must not enable Gen12
ports.
The Gen12 gate is necessary but insufficient: physical combo-B HPD/SST also
requires exact TGL/ADL-P/N GPU and actually observed matching PCH policy.

Intel-only crate builds (`--no-default-features --features intel`) and
their `kernel-test` fixtures use vendor feature guards throughout shared
DRM hooks and tests. AMD native placement admission cannot be constructed
without its backend; generic DRM/DP fixtures and the registration census
remain enabled. Intel media and MST modules likewise require `intel`.

### Lane Q6 (#1024) — display follow-ons

- **DBUF_CTL power sequencing** — the modeset requests power
  for both DBUF slices (`DBUF_CTL` S1 0x45008 / S2 0x44FE8,
  POWER_REQUEST bit 31 → POWER_STATE bit 30, addresses and
  fields from the display register volume / i915
  `skl_watermark_regs.h`; they are not in PRM Vol. 12) before
  programming watermarks, and fails the modeset with
  `DbufPowerTimeout` if a slice never grants. The
  tracker-state-service fields are left at firmware values;
  their programming belongs to the MDCLK/CDCLK-ratio and
  joined-MBUS machinery (multi-pipe, #1017).
- **Latency-based watermarks** (`intel_gpu_wm`) — the Gen12
  algorithm: pcode memory latencies (`intel_gpu_pcode`,
  GEN9_PCODE_READ_MEM_LATENCY) sanitised / made monotonic /
  WaWmMemoryReadLatency-adjusted, method1/method2 selection,
  per-level blocks/lines with monotonic clamping,
  min_ddb_alloc validation against the plane's allocation,
  transition watermarks (wm0 + 14), and the SAGV watermark at
  (GEN12_PCODE_READ_SAGV_BLOCK_TIME_US + level-0 latency) in
  the dedicated SAGV registers (Gen12 has 6 regular levels).
  Scope: linear surfaces, one pipe, one plane — the plane
  receives the whole 2048-block DBUF (the degenerate
  single-consumer allocation); per-pipe slice arbitration is
  #1017. If the pcode latency read fails or level 0 is
  unusable, the modeset falls back to lane 1's pre-boot
  programming. SAGV *control* (pcode 0x21) stays with the
  bandwidth manager; this lane only consumes the block time.
- **DSSM reference-clock selection** — `program_dpll` reads
  DSSM (0x51004) bits [31:29] (0 → 24 MHz, 1 → 19.2 MHz,
  2 → 38.4 MHz; reserved encodings fall through to 24 MHz,
  mirroring i915 `icl_readout_refclk`) and picks the matching
  combo-PLL row family: the 24 MHz rows (DCO int 0x151 /
  frac 0x4000) alongside lane 1's 19.2/38.4 MHz rows, with
  identical P/K/Q dividers. The PRM table's intermediate
  rates (2.16 / 4.32 / 6.48 Gbps) use distinct DCO rows and
  are not in the link-training ladder; they remain unencoded.
- **Scripted-DPCD full-modeset fixture** — the modeset tests
  carry a stateful sink model (register file with computed
  status bits, a pcode endpoint, and an AUX engine driving a
  DP training state machine + EDID EEPROM) over which
  `Modeset::modeset()` runs end-to-end: EDID mode returned,
  family-correct CFGCR0, hand-computed watermark words, and
  the TPS1 → TPS3 → off pattern history with the
  sink-requested swing applied. Q4's branch (#1114) grows a
  sibling sink model at the DP-codec layer; the two should be
  unified once both are on main.

## 8. Command submission (Stage 5 — `intel_gpu_rcs`)

The RCS0 execlists engine model and kernel submission helper for Gen12,
verified for Gen11 (Ice Lake) in the Gen11 execlists lane.
Compiled only under the GPU crate's `intel` feature. This is not a complete
userspace render backend (see §19). The corrected Gen12 restore template has
13 initial register pairs, engine-relative LRI selectors and extended render
state groups, ending at dword 0xb9; XCS ends at 0x34. The Gen11 template
follows `intel_lrc.c` `gen11_rcs_offsets` / `gen9_xcs_offsets` instead: a
15-pair (RCS) / 14-pair (XCS) first group carrying the second-level batch
registers Gen12 drops and no `0x2b4`, a single-pair `0x1b0` third group on
RCS, no 51-register extended group (RCS ends at dword 0x44), and an XCS
44-register group ending at dword 0xaa. The render image is 14 pages on
both generations (`intel_engine_context_size` returns
`GEN11_LR_CONTEXT_RENDER_SIZE` for graphics 11 and 12 alike), so the
48-page allocation bounds Gen11 with no per-generation bound; the CSB
depth is 12 from graphics 11 on (`GEN11_CSB_ENTRIES`). The indirect-context
offset default is Gen11 `0x1a` / Gen12 `0xd` (`intel_lrc_reg.h`), programmed
`<< 6` into the Gen11 RCS template; Gen12 keeps its existing zero template
value, and the pointer slot stays zero on both (Gen11 has no indirect-context
batch — Linux `lrc_init_wa_ctx` returns early for graphics 11). RING_CTL uses byte size
minus one page (128 KiB encodes 0x1f001) and the CSB has 12 entries. Fixed
source-cited vectors pin these values separately from the hardware model.
The Gen9 template follows `intel_lrc.c` `gen9_rcs_offsets` /
`gen9_xcs_offsets` instead: a 14-pair first group on RCS as well
as XCS (Gen9 RCS has no trailing `0x180`), no `0x1b0` third
group, a single-pair `R_PWR_CLK_STATE` group (`LRI(1, 0)`,
engine-relative `0xc8`) at dword 0x41, and — unlike Gen11 RCS —
the full 44-register extended group at 0x51, so Gen9 RCS ends
at dword 0xaa like XCS. The LRI headers carry no
`MI_LRI_LRM_CS_MMIO` bit (`set_offsets` sets it only for
graphics 11+). The render image is 22 pages on Gen9
(`GEN9_LR_CONTEXT_RENDER_SIZE`), still bounded by the 48-page
allocation; the CSB depth is 6 (`GEN8_CSB_ENTRIES`) with the
write pointer at dword 0x1f (`I915_HWS_CSB_WRITE_INDEX` —
the 0x2f location is the Gen11+ `ICL_HWS_CSB_WRITE_INDEX`).
The indirect-context offset default is Gen9 `0x26`,
programmed `<< 6` into the Gen9 RCS template, and Gen9 —
unlike Gen11 — has an indirect-context batch:
`gen9_init_indirectctx_bb` (MI_ARB_DISABLE, the coherent-L3
save/load/pipe-control/restore, the ClearSlm pipe-control,
the three chicken fixes, and on pooled-EU parts the media-pool
sequence, then MI_ARB_ENABLE), emitted by
`gen9_init_indirectctx_bb` and programmed into the template
by `setup_gen9_indirect_ctx`. The Gen9 context descriptor's
upper dword carries the SW context id at bits 37:47 and
nothing else — no engine instance/class fields (those are
ORed in only for graphics 11+); the CSB "switched to/away"
fields name the SW id on both generations (Linux parses both
with the same `gen8_csb_parse`). The Gen9 media engines are
VCS0/VCS1/VECS0 (GT3+ mask; GT1/GT2 parts carry VCS0 only —
the trim is first-silicon work) at the pre-Gen11 ring bases
(0x12000 / 0x1c000 / 0x1a000), driven through the aggregate
media forcewake domain (Lane 6's `GEN9_FW_DOMAINS` table:
0xA270, ack 0x0D88) since Gen9 has
no per-VDBox sub-domains. `install_gen9_wa_bb` builds the WA
batch once per engine against a GT scratch page (the
`lrc_init_wa_ctx` equivalent, including the dword the
coherent-L3 workaround saves to), and `create_context` points
each Gen9 RCS context's indirect-context slot at it.
Public interface:

- `RcsEngine::new(mmio, alloc)` — allocate the engine status
  page, program `RING_HWS_PGA`, adopt the hardware CSB write
  pointer. Generic over `MmioWindow` + `GpuAllocator` so the
  protocol is fixture-drivable without a BAR; production uses
  `BarWindow` + `GgttArena`. `new_for_generation` /
  `with_spec_for_generation` select the Gen11 context-image
  template for `Generation::IceLake`; the plain constructors
  keep the Gen12 template.
- `create_context() -> ContextId` / `destroy_context(id)` —
  a context owns a 48-page LRC image (register-state template
  on page 1), a 128 KiB ring, and a 1-page HWSP. Handles pack
  slot + generation; a stale handle is `UnknownContext`, never
  an alias. Destroy refuses (`ContextBusy`) while the context
  is loaded or has work queued/in flight.
- `write_batch(dwords) -> BatchBuf` — GGTT batch allocation;
  the batch must end with `MI_BATCH_BUFFER_END`.
- `submit(ctx, batch) -> request id` — appends
  `MI_BATCH_BUFFER_START` (GGTT), a render-cache drain/stall and a separate
  PIPE_CONTROL GGTT post-sync breadcrumb (XCS uses MI_FLUSH_DW), advances the
  image tail, and pumps the execlist ports. The context must
  be idle: this driver never patches an image the hardware
  may be restoring or saving, so re-submitting to a loaded
  context is `ContextBusy` (queued-but-unloaded contexts
  accept further submits and are covered together).
- `submit_resident(ctx, ResidentBatch) -> ResidentSubmission` — owns arbitrary
  PPGTT batch placement and its complete residency until verified retirement.
  A resident context must have no queued or loaded work. Returns a request ID
  and a cancellation-safe `CompletionFence`; see `spec.md` §3 for loss/reset.
- `poll_completions() -> Vec<CompletedRequest>` — drains the
  Gen12 CSB from the engine status page (promote / preempt /
  complete), verifies the final breadcrumb and saved ring head, retires
  requests, frees batch allocations, and
  pumps the next ports. `wait_seqno_async` samples through timer awaits;
  `wait_seqno` is its spin-safe sync bridge outside executor polls.
  Production glue: `submit_dwords` /
  `poll_default_completions` attach lazily to the probed
  controller on a default context. The legacy submission lease
  admits Tiger Lake, Alder Lake, Ice Lake and Skylake; `attach_default`
  builds the engine for the probed generation, so a Gen11 part
  gets the Gen11 template and a Gen9 part the Gen9 template. `GraphicsIp::read` has a pre-GMD
  arm for Gen11 (version 1100, no MMIO touch) — the Lane 1
  remainder — so the context-seed and GuC paths that sample
  the graphics IP work on Gen11 without reading `GMD_ID`.
- `attach_ppgtt(ctx, root_phys)` / `detach_ppgtt(ctx)` /
  `ppgtt_root(ctx)` — program a PPGTT root (§9) into the
  context image's PDP0 pair. Idle-context discipline, like
  every image patch here: a loaded or covered context refuses
  with `ContextBusy`, including queued requests; an unaligned or >46-bit root is
  `InvalidPpgttRoot`.

Invariants:

- ELSP writes are always full pairs in hardware order
  (port 1 high/low, port 0 high/low, posting read); a zero
  descriptor marks an empty port.
- Contexts address via GGTT by default: descriptor mode
  Legacy-64B, PDP image fields zero, batch ASI = GGTT. With
  a PPGTT root attached (§9) the PDP0 pair carries the raw root address
  and the hardware walk runs under the context; batch
  allocations from `write_batch` remain GGTT-backed; `submit_ppgtt` uses their
  identity VA, whereas `submit_resident` uses the admitted arbitrary PPGTT VA.
- A context's requests retire strictly in submission order;
  a preempted context's covered requests return to the queue
  front and are resubmitted, never retired early.
- Every allocation (image / ring / HWSP / batch / status
  page) is arena-accounted; destroy and retirement return
  the arena to its prior balance.
- Missing breadcrumb/head proof sets `CompletionLost` and stops publication
  without completing fences or releasing resident tables/BOs. A context's CSB
  software identity is not reused during the engine lifetime. Proven hardware
  reset is the only alternate release path; pending fences report reset error.
- Qword-aligned ring tails include wrap-padding in capacity checks. Hardware
  release/acquire barriers order the submission doorbell and CSB publication.

Flagged for first-silicon verification (single named
constants in `intel_gpu_rcs`): `CSB_ENTRIES` = 12 (Gen11+
CSB depth; Gen9 is 6, `GEN9_CSB_ENTRIES`, with the write
pointer at dword 0x1f), `RCS_IMAGE_PAGES` = 48 (allocation
bound above the hardware image size — 14 pages Gen11/Gen12,
22 pages Gen9), and the descriptor Legacy-64B
mode choice. The Gen11 template, indirect-offset default,
image bound and pre-GMD identity read are fixture-verified
against the Linux Gen11 tables in this lane; the Gen9
template, 0x26 indirect offset, 6-entry CSB, 22-page image,
WA batch and Gen9 descriptor upper dword (SW id only, no
instance/class) are fixture-verified against the Linux Gen9
tables the same way; first silicon
execution on Gen9 hardware is still outstanding (Daniel's
bringup lane). One pre-existing NARF-wide deviation is
recorded, not changed: the descriptor sets bit 5
(`DESC_L3LLC_COHERENT`) on every generation, while Linux
`lrc_descriptor` sets it only for graphics 8. The Gen12
submission path ships with the bit set, so the lane keeps
Gen11 identical to the verified Gen12 descriptor rather than
diverging on an untested hunch; the Gen9 lane re-grounded
the descriptor and keeps Gen9 under the same policy.

## 9. PPGTT + GGTT discipline (Stage 4/5 — `intel_gpu_ppgtt`, #1012)

The per-process page-table walker for Gen12, plus the GGTT
installation discipline the issue names. Compiled only under
the gpu crate's `intel` feature. Sources: TGL PRM Vol. 5
§"Memory Views" (walk levels, entry format) and §"GTTMMADR"
(GGTT window layout).

Public interface:

- `Ppgtt::new(mem)` — an empty address space owning one
  allocated PML4 root page. `root_phys()` is the value a
  context programs as its PPGTT root (§8's
  `RcsEngine::attach_ppgtt`).
- `map(mem, va, phys, pat, writable)` / `unmap(mem, va)` —
  4 KiB leaf mappings over the 48-bit VA space (levels
  PML4 → PDPT → PD → PT, 512 entries per table). Double
  mapping is `AlreadyMapped`; unmapping an absent VA is
  `NotMapped`. Intermediate tables are created on first use
  and freed when an unmap leaves them empty.
- `translate(mem, va) -> WalkOutcome` — the hardware walk,
  CPU-side: `Mapped(phys)`, `NotMapped { level }`, or
  `Corrupt { level }`. Present-but-malformed entries
  (reserved bits outside the level's documented encoding, or
  a zero physical address) are never followed.
- `teardown(mem)` — frees every owned table page; leaf
  frames are the caller's and are never freed by the walker.
- `PtMemory` — the table-page seam, addressed physically
  exactly as the hardware walk is. Production is
  `FramePtMemory` (host frames, direct-map CPU access);
  fixtures model system RAM and cross-check translations
  against an independent reference walk written from the PRM
  level definition.
- GGTT discipline in `intel_gpu_gtt`: `ggtt_va_size(bar_len)`
  derives the GGTT size from the actual GTTMMADR BAR length
  (16 MiB BAR → 4 GiB GGTT); every scanout mapping is
  bounds-checked against it (`GttError::OutOfBounds`) before
  any write, and every PTE write burst ends with
  `flush_ggtt_writes` (fence + readback of the last slot).

Invariants:

- A `Ppgtt` owns exactly the tables it allocated —
  `table_pages()` and the allocator's `live_tables()` agree
  at every public boundary, including after a map that fails
  partway (`OutOfMemory` leaves a well-formed partial chain).
- The walker never writes a leaf or intermediate entry it did
  not encode itself from validated inputs; foreign entries it
  cannot validate stop the walk as `Corrupt`, on both the
  translate and map paths.
- Context integration is one-directional: the RCS engine
  programs a root the walker produced; the walker knows
  nothing of contexts. Batch submission through a PPGTT (VA
  batches) is not claimed here — batches remain GGTT-backed
  (§8); the media lane (#1022) is the named consumer that
  builds on per-context PPGTT.

In 4-level mode the context's **PDP0** pair carries the raw PML4
physical address; PDP1–PDP3 remain zero. This is a register value,
not a PTE. Source: MIT i915 `gt/intel_lrc_reg.h` ASSIGN_CTX_PML4
and `gt/intel_lrc.c` lrc_update_regs (Linux v6.12). Native fixtures
check the literal register image. Hardware acceptance remains open.


## 10. eDP panel power sequencing + PSR (Stage 5 — `intel_gpu_edp`, #1020)

The internal-panel counterpart of the external-DP path
(§7 + Q4's session work): the eDP panel on DDI A is powered
by the PPS block and kept in Panel Self Refresh between
updates. Compiled only under the gpu crate's `intel`
feature. Sources: eDP 1.4b (DPCD field map, via
`drm_dp.h`), TGL PRM Vol. 2c + Vol. 12 displays volumes
(PPS/PSR register map and field encodings), with
`intel_pps.c` / `intel_psr.c` (+ their `*_regs.h`) from
Linux i915 read as cross-checks of the flows, not as the
source of the constants.

Public interface:

- `PanelPowerSequencer` — the PPS conversation over an
  `MmioWindow`. `new` adopts firmware-programmed delay
  fields verbatim; only zero fields (and the T8/T9 fields,
  which are forced to 1 because the waits run in software)
  fall back to the eDP spec's upper-limit defaults
  (`PanelDelays::SPEC_DEFAULTS`: T1+T3 210 ms, T8/T9 50 ms,
  T10 500 ms, T11+T12 610 ms). `init_registers` programs the
  delay registers and the PP_CONTROL cycle-delay field
  (100 ms granularity on CNP+ PCH — there is no PP_DIVISOR).
  `power_on` enforces the power cycle (status-side
  IDLE_CYCLE poll plus the software remainder of T11+T12
  from the recorded power-off stamp) before setting
  PANEL_POWER_ON, then waits for the on-idle state;
  `vdd_on`/`vdd_off` are the TCON/VDD discipline;
  `backlight_on`/`backlight_off` gate EDP_BLC_ENABLE with
  T8/T9 observed in software. A panel that misses its
  on-idle budget is left powered-down (power target and
  VDD-force cleared) with a typed `PpsError`; the backlight
  gate never opens for an unpowered panel.
- `PsrCaps::probe` — one burst read of DPCD 0x070..0x074
  plus the sync-latency byte at 0x2009. Support 0 or a
  reserved value (>4) declines as `Ok(None)` — plain eDP,
  zero PSR traffic. A claiming panel with a reserved
  setup-time code (7) is refused with a typed error.
  Granularity bytes are honoured only when the sink
  requires programmed granularity; zero fields fall back
  to 4×4 rather than propagating a divide-by-zero.
- `psr_enable` / `psr_disable` — the enable conversation:
  entry-setup validity is checked against the mode's
  vertical blanking before any write; PSR2 programs the
  sink (ALPM_CONFIG, then PSR_EN_CFG, then SET_POWER D0),
  writes PSR1's CTL disabled, then PSR2_CTL + MAN_TRK in
  continuous full frame. PSR2 falls back to PSR1 when the
  mode's scanlines make the BSpec wake times (42/45 µs)
  exceed 12 lines. PSR1 programs EN_CFG 0x07
  (ENABLE|MAIN_LINK_ACTIVE|CRC) + SET_POWER D0, then the
  source CTL. TP intervals use the conservative 2500 µs
  bucket (no VBT in this driver); idle frames follow
  i915's formula `max(6, sink_sync_latency + 1)`, frames
  before SU `max(sink_sync_latency + 1, 2)` (+1 past the
  entry-setup count). Disable runs source-first, then
  clears the sink byte.
- The runtime seam — `runtime_install_panel`,
  `runtime_install_psr`, `set_flip_pending`,
  `notify_scanout_dirty`, `on_scanout_published` — is how
  the framebuffer publish path drives PSR: a scanout
  publish notifies a full-frame update (which is what
  exits PSR), a region notify drives PSR2 selective
  update, and nothing polls. A notify while a flip is
  pending is refused before any register write. Probe
  wiring: PPS runs first inside the display block of
  `intel_gpu::probe` (a failed sequence skips backlight
  install, takeover, and the scanout move entirely), PSR
  is attempted once a real mode exists, and
  `publish_scanout` calls `on_scanout_published` with no
  locks held. `panel_power_off` composes the shutdown:
  registered backlight brightness to zero
  (`narf_drivers_backlight::panel_owner`, the #1037
  composition seam), PSR disable, then the PPS T9 → T10
  sequence.

Invariants:

- The MAN_TRK value for a partial update encodes exactly
  the granularity-aligned dirtied region (outward-aligned
  to the sink's SU granularity, TGL additionally to
  4 lines) — never the full frame. The fixture suite
  asserts both platform encodings byte-for-value.
- No PSR register or DPCD byte is written for a panel that
  did not claim PSR, and no PPS step is skipped: cycle
  delay before power-on, T8 before the backlight gate,
  backlight gate closed (and T9 observed) before power
  drops.
- Lock order is CONTROLLER → EDP_RUNTIME; the runtime
  lock is never held across an AUX transaction or a
  console write, and the MMIO window passed to
  `notify_scanout_dirty` is caller-built from the BAR
  (same discipline as takeover's adapter).

Composition points and named omissions:

- PSR2 selective fetch's plane registers
  (PLANE_SEL_FETCH_*) belong to lane 1's plane-programming
  surface; MAN_TRK is the SU discipline implemented here,
  and sel-fetch composition lands with the plane lane.
  On display 14 none of this module's PSR runs: the probe
  enable is Gen12-only (its PSR2_CTL layout is not display
  14's), and PSR1 is driven by the KMS owner through
  `intel_gpu_psr` (§20, "Display-14 PSR1 under KMS
  ownership"). That owner, unlike this module, reads the
  VBT: eDP PSR needs the panel's VBT `psr.enable` and
  takes the VBT TP wake times and idle frames (§20,
  "Display-14 PSR inputs, VBT gate and off-path FBC
  carve"). The same owner runs PSR2 with selective
  fetch on display 14, including the primary's
  `SEL_FETCH_PLANE_*` and the cursor's
  `SEL_FETCH_CUR_CTL`, from each commit's frame damage
  (§20, "Display-14 PSR2 selective update and frame
  damage"). Panel Replay is not offered on display 14.
- On display 14, `notify_scanout_dirty` takes a DC_off
  reference (§12.1) before `EDP_RUNTIME` and releases it
  after, so a PSR2 SU write never reaches a power-gated
  transcoder; a failed DC exit refuses with
  `PsrError::Unavailable` before any PSR write.
- ADL-P stepping workaround Wa_22012278275 (scrambled
  early-transport map) is not applied: this driver has no
  stepping readout yet.
- Sink sync latency is read from the last-actual field of
  DP_SYNCHRONIZATION_LATENCY_IN_SINK (bits [7:4]); i915's
  max-latency field (bits [3:0]) is the alternative —
  flagged for first-silicon verification, as is the
  PCH PPS base (0xC7200) on the south-display SKUs this
  queue covers.

### 10.5 DPCD backlight device (wave-2 backfill — `intel_dpcd_bl`, #957)

`intel_dpcd_bl` retains the legacy explicit-width `install(channel, lsb_used)`
scaffold and now connects a qualified production MTL/Arrow full-AUX VESA SDR
owner to the existing arbitrated backlight stack. Gen12 PWM admission is
unchanged. The production owner requires a live owned Pipe-A internal-panel
route, actual current PCI authority/D0/PPS, an initially open PPS gate and source-qualified eDP capability,
mode and bit-count observations. Mixed PWM/product, luminance and proprietary
HDR paths remain refused; firmware must already use the supported DPCD mode.

The pinned MIT Linux `b90c984d` `drm_dp_helper.c` and `drm_dp.h` supply the
previously missing literal caps/mode/enable contracts. Brightness uses exactly
one or two MSB-first bytes at0x722, with maximum derived from the retained
PWMGEN bit count rather than the register width alone. For 8-bit panels NARF
omits the unused LSB; the pinned Linux helper writes a second zero byte.
The owner retains mode, frequency and capability identity and requires exact readback before
confirming a changed level. Only the elected backlight candidate may write.
Disabled firmware control initializes effective intent to zero despite a
stale stored level; initial closed-gate adoption refuses without writes.
A shared nonblocking AUX mutex serializes hardware transactions with EDID,
PSR and link services; inherited SEND_BUSY refuses before register writes.

Latest brightness intent survives worker contention and panel parking.
Suspend/relight uses the actual PPS gate and retained timing deadlines, without
bridging an executor poll through `block_on`. Fresh video/console publication
must explicitly admit relight before the worker can restore and verify DPCD
state and reopen the gate. Unavailable access or uncertain writes keep the
owner parked/failed with its intent retained. This profile does not close
mixed-control panels, external outputs or the broader display power backlog.

## 11. Forcewake domains (Stage 5 — `intel_gpu_forcewake`, #1013)

Register access under GT power gating. Compiled only under
the gpu crate's `intel` feature. Forcewake is the driver's
lever on the per-block power gates that sit in front of most
GT registers; it is distinct from the display power wells
(§7's PG1/PG2 machinery), which power the display block and
take no forcewake. Sources: the i915 uncore layer
(`intel_uncore.c`, `i915_reg.h`) — the authoritative
restatement of the PRM Vol. 12 forcewake registers.

Register map (Gen9-named, used for the Gen11/Gen12 domain
table): request registers `FORCEWAKE_BLITTER` = 0xA188 (the
legacy FORCEWAKE_MT register), `FORCEWAKE_MEDIA` = 0xA270,
`FORCEWAKE_RENDER` = 0xA278; ack registers render 0x0D84,
media 0x0D88, blitter 0x130044. The request bit is
`FORCEWAKE_KERNEL` = BIT(0); BIT(1) is another requestor's
(`FORCEWAKE_USER`). Writes are masked (value in the low
half, per-bit write mask in the high half), so one requestor
never disturbs another's bits.

Public interface:

- `Forcewake::new()` — per-domain hold counts (render,
  blitter, media), no window owned; every operation takes
  the caller's `&M: MmioWindow`, so the manager composes
  with any register path (engine window, production
  `BarWindow`, fixture).
- `acquire(regs, domain)` / `release(regs, domain)` —
  refcounted holds. Only the 0→1 transition programs the
  request (masked-enable + ack wait); only the 1→0
  transition programs the clear (masked-disable + ack-clear
  wait). `with_domain(regs, domain, f)` is the scoped form.
- `sanitize(regs)` — probe-time reset mirroring i915's
  `fw_domain_reset`: masked-clear of all request bits in
  every domain, counts zeroed, no ack waits (a domain's
  well may not exist on fused-off parts).

Invariants:

- A domain is never dropped under another holder: nested
  acquires generate exactly one hardware request, and the
  clear is programmed only at the last release.
- No leaked hold on timeout: if the ack never sets — after
  the one clear→set re-kick i915 documents for the
  lost-ack quirk (the driver's request colliding with the
  hardware's own wake requests) — acquire rolls the
  request back off and errors with the count still zero.
- An ack-clear timeout on release is reported, but the
  hold is dropped: the request is off and the hardware is
  merely slow to gate (the safe direction).
- Ack waits are poll-counted (`ACK_POLL_BUDGET` = 100 000
  polls ≫ i915's `FORCEWAKE_ACK_TIMEOUT_MS` = 50 at
  silicon MMIO-read cost), never wall-clock deadlines, so
  fixtures that model ack latency in polls are
  deterministic under TCG.

Composition: the RCS production glue
(`intel_gpu_rcs::submit_dwords`) carries a `Forcewake` in
the default engine's state, sanitized at attach, and runs
each submission inside a render-domain hold — the RCS0
register conversation is the GT access the PRM gates.
`poll_default_completions` takes no hold (the CSB lives in
host memory, not a gated register); probe's presence reads
are always-on-block reads and stay unwrapped. Deliberate
divergence from i915: the clear is programmed immediately
at the last release rather than deferred ~1 ms by timer —
a host-OS batching optimisation, not hardware protocol.

Out of scope here: the per-engine media sub-domains
(VDBOX/VEBOX) belong to the media-engines work (#1022);
RC6 residency policy builds on these holds (#1014).

## 12. RC6 + DMC (Stage 5 — `intel_gpu_rc6`, `intel_gpu_dmc`, #1014)

Idle power for the GT and the display: RC6 (the GT's deep
idle state, host-programmed thresholds + park/unpark
discipline) and the DMC firmware machinery (container
parse/validate, program load, and the DC5/DC6 handoff the
loaded program enables). Compiled only under the gpu
crate's `intel` feature. Sources: i915's
`gt/intel_rc6.c`, `gt/intel_gt_regs.h`,
`gt/intel_engine_regs.h`, `display/intel_dmc.c`,
`display/intel_dmc_regs.h` and
`display/intel_display_regs.h` — the authoritative
restatement of the PRM power registers and the DMC
firmware format (torvalds/linux master, 2026-10-27).

RC6 register map: `GEN6_RC_CONTROL` = 0xA090,
`GEN6_RC_STATE` = 0xA094, wake-rate limits 0xA09C /
0xA0A0, evaluation interval 0xA0A8, idle hysteresis
0xA0AC, `GEN6_RC_SLEEP` = 0xA0B0, `GEN6_RC6_THRESHOLD` =
0xA0B8, PG idle hysteresis 0xA0C4 / 0xA0C8,
`GEN9_PG_ENABLE` = 0xA210, residency counter
`GEN6_GT_GFX_RC6` = 0x138108 (32-bit, 1.28 µs units on
Gen11/12). The enable sequence is `gen11_rc6_enable`'s:
wake-rate limits (54≪16|85, media 150), evaluation
interval 125000, hysteresis 25, `RING_MAX_IDLE` = 10 per
present engine, RC sleep 0, threshold 50000, media/render
PG hysteresis 60, then `GEN9_PG_ENABLE` = render + media
+ media-sampler coarse gating plus per-VCS VDN HCP/MFX
bits — all under FORCEWAKE_ALL. This legacy helper uses
host-owned RC6 without a GuC owner: the control value is
`HW_ENABLE | RC6_ENABLE | EI_MODE(1)` = 0x8804_0000
(i915's host-owned form). The one omitted write from
i915's sequence is `GUC_MAX_IDLE_COUNT` — it programs
the GuC's idle policy, which this helper does not own, and
its offset could not be grounded from the sources
consulted; the omission is deliberate, not an oversight.
Park writes `RC6_ENABLE` alone plus target state 4
(normal RC6) in `RC_STATE` [18:16]; unpark restores the
full control value; disable/sanitize zero PG_ENABLE,
RC_CONTROL and RC_STATE (the `__intel_rc6_disable`
conversation).

DMC format: CSS header (128 bytes; `module_type` 0x09,
`header_ver` 0x10000, firmware version at dword 22),
package header (version 1 ≤ 20 / version 2 ≤ 32 FW-info
entries; the table always occupies the max count;
`num_entries` clamps), FW-info stepping match with `'*'`
wildcards, first match per id wins. Program headers:
signature 0x40403E3E; versions 1 (128-byte header,
`header_len` in *bytes*, ≤ 8 MMIO pairs, payload loads
at 0x80000) and 3 (256-byte header, `header_len` in
dwords, ≤ 20 pairs, explicit start address). Gen12
payload ceiling 0x6000 bytes. MMIO init addresses and v3
load windows are sanity-ranged per id (main program
0x80000–0x86FFF; pipe A 0x90000–0x96FFF; pipe B
0x98000–0x9EFFF). Event handlers: 8 per DMC on Gen12,
EVT_HTP at reg-base +0x004 / EVT_CTL at +0x034 (main
0x8F000; pipes 0x92000 + 0x400·(id−1)); the disabled
EVT_CTL encoding is TYPE=EDGE_0_1 | EVENT=FALSE =
0x0003_0100, and `evt_ctl_disable` preserves only the
sticky ENABLE bit. Load (`dmc_load_program`): handler
sweep → payload dword stream → MMIO table, per program,
then the DC_STATE_DEBUG mask bits (CORES | MEMORY_UP)
plus a posting read. Load-time transforms: pipe event
entries always written disabled; on the main DMC the
CLK_MSEC and VBLANK_DELAYED_A handlers written disabled;
at *parse* time the TGL fixup rewrites a main-DMC
VBLANK_A handler pair to VBLANK_DELAYED_A (shipped
firmware erratum). DC handoff: `DC_STATE_EN` = 0x45504,
target field [1:0] (1 = DC5, 2 = DC6); TGL DC5/DC6 entry
counters at 0x101084 / 0x101088.

Public interface:

- `Rc6::{sanitize, enable, disable}` — the conversations
  above, bracketed by FORCEWAKE_ALL holds on the caller's
  `Forcewake` (acquire render→blitter→media, release in
  reverse; a failed acquire rolls back and changes no
  state). `enable` takes the present engines' register
  bases plus the VCS count — production is `&[RCS_BASE]`,
  0 today.
- `Rc6::{park, unpark}` — the activity discipline.
  `unpark`'s control write runs inside a render hold.
  `park` is refused (`DomainsHeld`) while *any* domain is
  held and (`NotEnabled`) before enable; a refused park
  writes nothing.
- `Rc6Residency::{update, sample}` — wrap-safe delta
  accumulation (×1280 ns) of the hardware counter; the
  first sample primes. `sample` reads under a render
  hold.
- `parse_dmc_firmware(blob, stepping, substepping,
  max_fw_size)` — pure validation → `DmcFirmware`
  (payloads borrowed from the blob; per-slot programs;
  `skipped_mask`). No MMIO: refusal means nothing was
  written anywhere.
- `load_program` / `disable_program` / `verify_loaded` —
  the load conversation over the caller's window;
  verification is i915's `assert_dmc_loaded` as an error
  return (program-RAM first dword + every MMIO entry,
  post-transform).
- `set_dc_target(fw, DcTarget)` — RMW of `DC_STATE_EN`'s
  field; DC5/DC6 refused (`NoMainProgram`) with no main
  program loaded.
- `intel_gpu_gen12_dmc::load_for_display(mmio, family,
  authority)` — the probe-time wiring (`intel_dmc_init` +
  `dmc_load_work_fn`): resolves the platform blob name
  (TGL `i915/tgl_dmc_ver2_12.bin`, RKL
  `i915/rkl_dmc_ver2_03.bin`, ADL-S `i915/adls_dmc_ver2_01.bin`,
  ADL-P `i915/adlp_dmc.bin` with fallback
  `i915/adlp_dmc_ver2_16.bin`; ADL-N takes the ADL-P pair as
  its subplatform), fetches it from the firmware registry,
  parses/loads/verifies via the interface above, and
  registers the resident copy with the PM core for the
  resume reload. Non-fatal: any failure only disables
  runtime power management and the display still modesets.
  DG1 has no Gen12 modeset path and is not wired.

Invariants:

- RC6 is never armed under a forcewake hold: the park
  refusal reads the live hold counts, so a submission
  inside its render hold cannot be gated away mid-flight,
  and park succeeds again the moment holders drain.
- The DMC parser never partially succeeds into hardware:
  it is pure, and every refusal (truncation, bad
  signature/module type/version, MMIO or load-address
  range escape, oversize or empty payload) precedes any
  register write. Pipe-program defects degrade to an
  empty slot (i915's tolerance); main-program defects are
  hard errors.
- Where this implementation is stricter than i915 it
  says so in the code: the DMC signature and CSS
  module-type/version are enforced (i915's current parser
  does not check them; the format documents both as
  constants), and PIPEC/PIPED programs are skipped rather
  than range-checked against an ungrounded Gen12 window
  (their skip is recorded in `skipped_mask`).
- Residency totals are monotonic across counter wrap by
  construction (wrapping-sub deltas); no clock is
  consulted anywhere in this section's paths, so fixtures
  are deterministic under TCG.

Composition: both modules own no window and compose over
the caller's `&M: MmioWindow` + `Forcewake` — the seam
§11 designed for. No new initcalls and no change to the
registered-initcall census: these are library state
machines the controller (and the future runtime-PM lane)
compose next to the RCS engine's forcewake state. The
firmware blob arrives as a byte slice; sourcing blobs
from storage is the platform's business, not this
module's — the Gen12 probe wiring
(`intel_gpu_gen12_dmc`) is the one production consumer
so far: it runs before the first modeset on the
integrated display path and registers the resident copy
with the PM core, so suspend/resume reloads it.

Out of scope here: GuC-owned RC and `GUC_MAX_IDLE_COUNT`
(separate retained GuC owner); RC6p/RC6pp (absent on Gen12); runtime
event-handler reconfiguration (PSR/DCB routing belongs
to the display pipeline); DC3CO/DC9 targets; ADL-P
(display 13) pipe-DMC ranges; wiring park/unpark to GT
activity (the runtime-PM lane consumes this interface).

### 12.1 Display 14 DMC and DC states (`intel_gpu_dc_states`)

Meteor Lake and Arrow Lake (display 14.00) have a production DC-state
service; the Gen12 rules, tests and the §13 seam above are unchanged. The
display-20, -30 and -35 owners create the same service with their own DMC
identity (§17, §5).
Sources are the pinned Linux tree b90c984d615e8ce2af96f5b1411a962d83fed2ad:
`intel_dmc.c`, `intel_dmc_regs.h`, `intel_display_power.c`,
`intel_display_power_well.c`, `intel_display_power_map.c`, `intel_display.c`,
`intel_cx0_phy.c`, `i915_reg.h` and `intel_backlight_regs.h`.

Firmware: `DmcPlatform::Xelpdp` validates `i915/mtl_dmc.bin` with the
`XELPDP_DMC_MAX_FW_SIZE` ceiling (0x7000), the main v3 MMIO table in
`TGL_MAIN_MMIO` (0x8F000–0x8FFFF), no TGL/ADL-S event fixups, and pipe event
handlers at 0x5F000 + 0x400·(id−1). Pipe MMIO tables must stay in
`ADLP_PIPE_MMIO` (0x5F000–0x5FFFF). The tree streams every payload to the
firmware's own start address without a bound, so this driver is stricter: the
main payload must lie in 0x80000–0x8EFFF, and each pipe payload in its slot
window (A 0x90000–0x96FFF, B 0x98000–0x9EFFF, C 0x52000–0x53FFF, D
0x59000–0x5AFFF). Those are the windows in which the shipped `mtl_dmc.bin`
(v2.23) places each pipe program and its `DMC_SSP_BASE` stack top. A pipe
program outside its window is recorded in `skipped_mask` and never loaded or
enabled. Load follows `intel_dmc_load_program` for display 14:
Wa_16015201720 (`GEN9_CLKGATE_DIS_0` 0x46530 gains bits 15 and 14), then for
the main program and every accepted pipe program the handler sweep, payload
and MMIO table (pipe events written disabled), then the `DC_STATE_DEBUG`
masks with a posting read, then `verify_loaded`. Disable is the same
workaround plus every program's sweep. Stepping selection is wildcard because
the driver has no display-stepping readout.

Pipe DMC follows `intel_dmc_enable_pipe` / `intel_dmc_disable_pipe`. A pipe
owner reports its pipe lit (`pipe_lit_for_bar`, after enabling it or adopting
it lit, as `intel_modeset_setup` sanitizes active pipes) and dark
(`pipe_dark_for_bar`, before disabling it). Each runs under a `PipeDmc`
reference. With a loaded program, enable re-applies the pipe C/D MMIO table
(`need_pipedmc_load_mmio`; the main DMC saves and restores pipes A/B), verifies
the pipe program and sets `PIPEDMC_ENABLE_MTL(pipe)` in `MTL_PIPEDMC_CONTROL`.
A pipe program that does not verify is not enabled (i915 only warns). Every
(re)load re-enables the lit pipes before its Load reference drops. Suspend
clears this driver's enables before the program disable, keeping the pipes
recorded lit for the post-resume reload. KMS install reports the owned
internal Pipe A lit. The Pipe B–D owner and the MTL modeset call the two hooks
for the pipes they light and darken.

The DC_off well: `DcCore` counts references per user (Init, Load, Modeset,
Kms, Psr, Suspend, Aux, ExternalRoute, External, PipeDmc). The first reference reads `DC_STATE_EN` (0x45504). If any
DC field is set, it writes `DC_STATE_DISABLE` with `gen9_write_dc_state`'s
discipline (rewrite until seven consecutive matching reads, at most 100
rewrites) before the holder touches hardware. A write that never sticks
refuses the holder with `DcError::DidNotStick` and is latched. The last release
only schedules re-entry 17 ms later (`intel_display_power_put_async_delay`). A
reference taken inside that window cancels it without a register write.
Re-entry runs from a spawned task with no caller lock held, and requires all of
the following:

- no reference is held, and no `DC_STATE_EN` write failure is latched;
- the program is loaded and its main program still verifies, as
  `assert_main_dmc_loaded` checks (a lost program is reloaded first; pipe C/D
  state is not kept across DC6, so pipe programs are not checked here);
- the sanitized target is nonzero (DC6 on display 14; DC3CO and DC9 are never
  targeted);
- the utility pin is not in PWM mode;
- `MTL_PIPEDMC_CONTROL` (0x45250) shows no enabled pipe DMC that this driver
  did not enable;
- no external route is live.

`gen9_set_dc_state` is mirrored, including display 14's DC6-allowed residency
from `DG1_DMC_DEBUG_DC5_COUNT` (0x134154) deltas and a counter for requests the
DMC ignored.

Production wiring on Meteor/Arrow Lake: KMS install creates the service and
holds Init, so DC states are exited. After each GT publication the card worker
acquires the container through the trusted firmware-registry authority as a
bounded (1 MiB), parse-validated copy. It then loads and verifies the program
under a Load reference and drops Init and any Suspend reference. The following
hold a reference for their whole hardware conversation: KMS sessions, legacy
guards, display recovery, format refresh, the MTL modeset (a failed DC exit is
`ModesetError::PowerWellTimeout`), PSR scanout notifications (a failed DC exit
is `PsrError::Unavailable`) and every full-AUX panel-backlight conversation
(AUX transaction, PPS gate, relight step; AUX_A is a DC_off domain, and a
refused reference reads as unavailable). The off-path FBC carve job (§20) holds
none: it reads only GGC, `STOLEN_RESERVED`, the media `GMD_ID` and
`GSCPSMI_BASE` and GGTT PTEs, which are GT-side registers, and each survey
chunk runs under the KMS mutex. System suspend preparation takes the Suspend
reference before the external, KMS and backlight quiesce. Once that succeeds it
disables the program; a failed preparation drops the reference again. The first
publication after resume reloads the retained container before release. Any
acquisition, validation or verification failure keeps Init held: DC0, wells up.

Not done here: PW_1, PW_A and AUX wells stay enabled by the modeset and are
never released (only DC_off is reference-counted). The pinned tree powers
display-14 AUX wells through `XELPDP_DP_AUX_CH_CTL` bit 19 (status bit 18); the
existing modeset's `PWR_WELL_CTL_AUX2` request is a divergence left to the AUX
owner. Suspend does not run display-core uninit (DBUF, CDCLK, PW_1 or the
`HOLD_PHY` latches) or DC9. DC3CO, flip queues, pipe DMC event
reconfiguration and display-stepping selection are not implemented. PCI runtime autosuspend with a
lit panel stays refused, as Linux's display wakeref keeps the function in D0;
DC5/DC6 is the lit-panel idle power path.

### 12.2 Gen11 power (Lane 6)

Gen11 idle power, verified against Linux 7.4-rc2 (commit
7475ea8b) rather than reused from the Gen12 modules:

- RC6 (`intel_gpu_rc6`): the Gen11/Gen12 enable sequence was
  already implemented; the lane re-verified every value
  against `gt/intel_rc6.c::gen11_rc6_enable` and fixed two
  divergences. `GUC_MAX_IDLE_COUNT` (0xC3E4,
  `gt/uc/intel_guc_reg.h:62`) = 0xA is now written after the
  `RING_MAX_IDLE` writes, as Linux does in the host-owned
  branch — the earlier omission (offset ungrounded) is gone.
  `GEN9_PG_ENABLE` on Gen11 is render + media + media-sampler
  only (0x7): Linux gates the per-VCS VDN HCP/MFX bits on
  `GRAPHICS_VER >= 12 && !IS_DG1`, so `Rc6::enable_gen11`
  programs no VDN bits however many video engines are
  present. All other values check out (wake-rate limit
  54<<16|85, media wake-rate 150, evaluation interval 125000,
  idle hysteresis 25, `RING_MAX_IDLE` 10, `RC_SLEEP` 0,
  RC6 threshold 50000, PG idle hysteresis 60/60 — the Gen11
  values, Gen9 used 250). The host-owned control value
  0x88040000 is correct for a driver with no GuC
  (`intel_guc_rc_enable` *enables* GuC RC and returns 0 on
  success, so the host-only branch is the failure arm).
  `enable_gen11` has no production caller: the Gen11
  execlists owner enables RC6 through `intel_gpu_legacy_power`
  (`gen11_rc6_enable`, §12.5).
- DC states (`intel_gpu_gen11_dc_states`): display 11 has its
  own mask, derived from
  `display/intel_display_power_well.c::gen9_dc_mask`
  (DISPLAY_VER == 11 adds UPTO_DC6 | DC9 to the UPTO_DC5
  base) and
  `display/intel_display_power.c::get_allowed_dc_mask`
  (max_dc 2, DC9 unconditional at ver >= 11, requested 2
  adds UPTO_DC6). The mask is UPTO_DC5 | UPTO_DC6 | DC9 =
  0xB, the allowed mask is DC9 | UPTO_DC6 = 0xA, the target
  is DC6. The grounding's "DC5|DC6 only" recollection is
  wrong — DC9 is in the mask; DC3CO joins only at display
  >= 12 and is stripped from tracking. The module is the mask
  + target + sticky-write core only: no `DC_off`
  refcounting, no DMC program lifecycle (those are the
  display-14 service's), and DC6 is armed only with a loaded
  ICL DMC program (`icl_dmc_ver1_09`, Lane 5's load).
- Forcewake (`intel_gpu_media`): the per-VDBox/VEBox
  sub-domains (`FORCEWAKE_MEDIA_VDBOX_GEN11(n)` 0xA540+4n,
  ack 0x0D50+4n; `FORCEWAKE_MEDIA_VEBOX_GEN11(n)` 0xA560+4n,
  ack 0x0D70+4n — `gt/intel_gt_regs.h:54-55, 922-923`) were
  already modelled generically over the instance, so no new
  domain code was needed. What was missing was the Gen11
  engine table: `GEN11_MEDIA_ENGINES` is VCS0/VCS2/VECS0
  (`i915_pci.c::icl_info`), VCS2 at `GEN11_BSD3_RING_BASE`
  0x1d0000 (`gt/intel_engine_cs.c`), taking `VdBox(2)`
  (request 0xA548, ack 0x0D58). `media_engines_for(Gen11)`
  now serves it, which wires the probe announce and
  `attach_media`; per-SKU fusing (a part with VCS2 fused
  off) is still unmodelled.
- SAGV (`intel_gpu_gen11_sagv`, `intel_gpu_gen11_wm`):
  on display 11 SAGV is controlled by restricting QGV
  points through `ICL_PCODE_SAGV_DE_MEM_SS_CONFIG` (0xe),
  not `GEN9_PCODE_SAGV_CONTROL` (0x21) — that is the
  pre-ICL (display 9) mechanism, and the Lane 4 watermark
  header's "(0x21)" is corrected here.
  `restrict_qgv_points` sends the allowed-points mask
  (bits [7:0]) and decodes the reply (SAFE 0 / POLL 1 /
  REJECTED 2), retrying POLL inside a 51 ms budget
  (Linux's 1 ms base + 50 ms fallback). Per-level admission
  is `can_sagv = latency >= sagv_block_time_us`
  (`display/skl_watermark.c::skl_compute_wm_levels`, only
  where there is no SAGV watermark register and the block
  time is nonzero), annotated by `apply_sagv_admission`;
  `can_enable_sagv` is the single-plane form of
  `skl_crtc_can_enable_sagv` (the highest enabled level must
  admit SAGV). Not done: the bandwidth-state machine that
  computes the QGV mask (QGV point inventory, data-rate
  calculation) and the pre/post-plane-update sequencing —
  `restrict_qgv_points` is the primitive it will call.
- D3cold / runtime PM: no Gen11 arm was needed.
  `intel_gpu_d3cold` is generation-independent (root-port
  PME + ACPI `_PR3` + VRAM threshold) and
  `intel_gpu_runtime_power` carries no generation gating;
  both were verified, not changed.

### 12.3 Gen11 external outputs (Lane 8)

The eighth and final Gen11 lane: the modeset-level external
outputs for Ice Lake, verified against Linux 7.4-rc2
(`drivers/gpu/drm/i915/display/`) and fixture-validated,
silicon untested. The 26-ID census (Lane 1) is unchanged —
no new fixture family was needed beyond the port-map and
register pins below.

- **Port map** (`intel_gpu_gen11_ddi::phy_for_port`):
  Ice Lake A/B are combo PHYs (DPLL0/DPLL1); C–F are Type-C
  ports TC1–TC4, each with its own MG PLL
  (`intel_port_to_phy`, `intel_phy_is_combo`,
  `intel_phy_is_tc`, `intel_port_to_tc`,
  `display/intel_display.c`; `icl_desc` port masks).
  Elkhart/Jasper Lake correct the task premise: A/B/C are
  combo PHYs and D shares PHY A with PORT_A
  (`intel_port_to_phy` special case); EHL/JSL have NO TC
  ports and NO MG PLLs (`ehl_plls[]` is DPLL0, DPLL1, DPLL4
  only). `DDI_BUF_CTL` addressing (0x64000 + port·0x100)
  is shared with Gen12 and reused. PORT_F exists only on
  `port_f` subplatform SKUs — the map describes the port
  when present; this driver does not model ICL subplatforms.
- **MG PLL** (`intel_gpu_gen11_dpll::mg_pll_state`,
  `mg_pll_write`, `mg_pll_enable`): the divisor search
  (`icl_mg_pll_find_divisors`: div1 ∈ {7, 5, 3, 2}, div2
  10→1, DCO = div1·div2·clock·5; DP forces the DCO to
  exactly 8.1 GHz, HDMI takes [7.992, 10] GHz) and the
  ICL MG packing (`icl_calc_mg_pll_state`, non-DKL branch,
  `use_ssc` false) into DIV0/DIV1/LF/FRAC_LOCK/SSC/BIAS/
  TDC_COLDST_BIAS at 0x168A00 + tc·0x1000, with the 38.4 MHz
  refclk write masks (BIAS untouched, COLDSTART only).
  The packing differs from the Dekel (DKL) layout — the
  divisor math is shared, the registers are not.
- **TBT PLL** (`tbt_pll_coeffs`, `tbt_pll_enable`): the
  fixed rows (`icl_tbt_pll_24MHz_values` /
  `icl_tbt_pll_19_2MHz_values`: 24 MHz → DCO 0x151/0x4000,
  19.2/38.4 MHz → 0x1A5/0x7000, P/5 K/1) at CFGCR0/1
  0x164100/0x164104 with `TBT_PLL_ENABLE` 0x46020.
- **MG PHY** (`intel_gpu_gen11_mg_phy::MgPort`): the Dekel
  port's public shape (`enable` / `route_clock` /
  `start_training` / `training_update` / `stop_transport` /
  `disable`) with Gen11 specifics — direct MMIO at
  0x168xxx + (tc−1)·0x1000 (no HIP bank, no FIA), the
  display-11 transcoder clock `(port+1) << 29`
  (`intel_ddi_enable_transcoder_clock`), the port-based
  `DP_TP_CTL` (DDI base + 0x40), the MG signal-level tables
  (`icl_get_mg_buf_trans`: RBR/HBR vs HBR2/HBR3 at 270 MHz,
  HDMI default entry 9), and `DDI_CLK_SEL_MG` + DPCLKA
  TC_CLK_OFF routing (`icl_ddi_tc_enable_clock`).
- **DP training reuse**: the training state machine
  (`display/intel_dp_link_training.c`) is generation-shared
  — no ICL-specific branches — and NARF mirrors it: the
  same `TrainingAux` callback shape serves combo and MG
  ports; only `set_signal_levels` dispatches by PHY. The
  modeset dispatches by `is_tc_port()` (Gen11 ICL C+,
  Gen12 D+).
- **HDMI**: `modeset_hdmi` no longer refuses Gen11. Combo
  ports take the WRPLL coefficients into the ICL combo PLL
  (DPLL0/1/4 by `combo_dpll_id`) with the ICL HDMI default
  levels; TC ports take the MG PLL (HDMI DCO rule at the
  TMDS clock) with the MG HDMI default levels.
- **Flips**: `external_display_supported()` and
  `backlight_supported()` admit Ice Lake. The backlight
  flip is grounded in Linux driving ICL through the same
  `cnp_pwm_funcs` (`bxt_set_backlight` /
  `bxt_get_backlight`): "CNP has the BXT implementation of
  backlight, but with only one controller" — CTL1/FREQ1/
  DUTY1 0xC8250/54/58, the block the install already
  programs. The install's controller-1 hardcoding is
  pre-existing Gen12 behavior (Linux takes the VBT
  controller, defaulting to 0).
- **Sessions and remainders**: the HPD / external-session
  layer admits Gen11 through `SourceFamily::Gen11` with the
  ICP hotplug bank (§7). EHL/JSL PORT_D shares PHY A and
  takes a PLL from the {DPLL4, DPLL1, DPLL0} pool per commit
  (`arbitrate_combo_dpll`, `icl_get_combo_phy_dpll`). Ice
  Lake TC ports claim the PHY through the FIA
  (`icl_tc_phy_ops`) for the DP-alt bridge; the TBT-alt
  clock route (`route_tbt_clock`) has no production caller.
  The MG `CRI_LOADGEN_SEL` FIXME (Linux does not program it
  either) and the VBT AFC-startup `div0` override are
  unmodelled. The EHL div-frac WA stays off (38.4 MHz ref on
  EHL B0+, stepping unmodelled).

### 12.4 Gen9 scope (Lane 0)

Gen9 (Skylake / Kaby Lake / Coffee Lake / Whiskey Lake /
Comet Lake, display 9) is admitted lane by lane on the Gen11
pattern: identity and probe (§5), execlists (§8), power
(§12.5), the modeset (§12.6) and the external outputs
(§12.7). Gen9 LP (Broxton / Gemini Lake) is described in §5.

- **Gen11-only, do NOT carry to Gen9**: the ICL combo
  PLL (CFGCR0 0x164000) + MG PLL + TBT PLL; the ICL
  CDCLK table / voltage levels; the ICL/EHL/JSL DDI
  tables; the Gen11 8-level watermark algorithm with
  DBUF 2048 / S1|S2; the ICL DMC 1.09 / 0x6000; the
  ICL/EHL GuC/HuC blobs; the QGV-point SAGV (0xe);
  per-VDBOX/VEBOX forcewake; the 36-bit PPGTT note
  (EHL/JSL only).
- **Recorded defaults**:
  - Q4 GuC requirement: DEFAULT execlists-only
    submission, GuC-optional, mirroring Gen11 (Lane 7
    after Lane 3). GuC submission stays optional on
    Gen9 by design; the GuC is loaded where a GuC owner
    exists, which is what HuC authentication requires.
    Profiles (Linux `gt/uc/intel_uc_fw.c`
    `INTEL_GUC_FIRMWARE_DEFS`): SKL `skl_guc_70.1.1`,
    KBL/CFL/CML-rev<5 `kbl_guc_70.1.1`, CML-rev≥5
    `cml_guc_70.1.1`, all at minimum 70.1.1. HuC
    (`INTEL_HUC_FIRMWARE_DEFS`): SKL `skl_huc_2.0.0`,
    KBL/CFL/CML-rev<5 `kbl_huc_4.0.0`, CML-rev≥5
    `cml_huc_4.0.0`. WOPCM total is 1 MiB on Gen9
    (`gt/intel_wopcm.c` `GEN9_WOPCM_SIZE`, vs 2 MiB
    from Gen11).
  - Q5 DMC requirement: DEFAULT REQUIRED for modeset,
    mirroring Gen12 — this differs from Gen11, whose
    load is best-effort / non-fatal. Blobs (Linux
    `display/intel_dmc.c:166-183`): SKL
    `skl_dmc_ver1_27`, KBL `kbl_dmc_ver1_04`, both with
    a 0x3000 per-program ceiling (`BXT_DMC_MAX_FW_SIZE`,
    half the ICL 0x6000). DMC gates DC5/DC6 entry, so a
    modeset that claims power states without it is
    incomplete.
  - Q6 CML revision split: the PCI revision ID. CML
    rev ≥ 5 takes the `cml_*` blobs, rev < 5 the KBL blobs
    (`intel_uc_fw.c:106-107,127-128`); the GT runtime
    passes the probe-read revision to the GuC and HuC
    opens (`open_for_revision`). Silicon untested: no
    rev ≥ 5 part has booted.

### 12.5 Gen9 power (Lane 6)

Gen9 idle power, verified against Linux 7.4-rc2 (commit
7475ea8b) rather than reused from the Gen11 modules — the
re-verification found five RC6 divergences and one DC-mask
correction:

- RC6 (`intel_gpu_rc6`, `enable_gen9`): `gen9_rc6_enable`
  is a different sequence from `gen11_rc6_enable`, not the
  same sequence with a different hysteresis. The wake-rate
  limit is platform-split — Skylake writes `108 << 16`
  (`WaRsDoubleRc6WrlWithCoarsePowerGating:skl`), every
  other Gen9 part writes `54 << 16` — and the
  `GEN10_MEDIA_WAKE_RATE_LIMIT` write (150) does not exist
  on this path at all. The coarse power-gating hysteresis
  is 250, not 60. `GEN6_RC6_THRESHOLD` is 37500 (37.5/125
  ms per EI), not 50000, and it is written *after* the
  hysteresis writes, not before them. `GEN9_PG_ENABLE` is
  render + media only (0x3): no media-sampler bit (that
  enable is Gen11+) and no VDN bits — and on Skylake
  GT3/GT4 parts the write is skipped entirely
  (`WaRsDisableCoarsePowerGating:skl,cnl`,
  `IS_SKYLAKE && (gt == 3 || gt == 4)`). The GT tier is
  not modelled yet, so `enable_gen9` takes the WA as an
  explicit caller input (`wa_disable_coarse_pg`); the
  sub-platform alone cannot derive it. Finally, after the
  sequence `intel_rc6_enable` zeroes `rc6->ctl_enable` for
  GRAPHICS_VER == 9 (`NEEDS_RC6_CTX_CORRUPTION_WA`), so
  Gen9 unpark writes 0 to `GEN6_RC_CONTROL`, not the
  host-owned 0x88040000 — `Rc6` now carries the
  enable-time control value and unpark restores it, while
  park still arms RC6 with the RC6-enable bit alone +
  target state 4 (its `manual` flag is latched from the
  pre-zeroed value). The park target stays 4 on Gen9:
  `has_rc6p` is 0 (Gen9 inherits `G75_FEATURES` via
  `GEN8_FEATURES`, "RC6p removed-by HSW") and `HAS_RC6pp`
  is always false. `enable_gen9` has no production caller:
  the execlists owner's RC6 and frequency requests are
  `intel_gpu_legacy_power` (`gen9_rc6_enable`,
  `gen11_rc6_enable`, `gen9_rps_enable`), which takes the
  SKL GT3/GT4 coarse power-gating WA from the PCI ID and
  steers the frequency from the job queue in place of RPS
  interrupts (efficient on unpark, RP0 after one busy
  up-evaluation interval, park after 5 ms idle). Gen9 LP
  reads `BXT_RP_STATE_CAP` and enables RC6 only behind
  `bxt_check_bios_rc6_setup`.
- DC states (`intel_gpu_gen9_dc_states`): display 9 has
  its own mask, derived from
  `display/intel_display_power_well.c::gen9_dc_mask` (the
  final `else` arm — the one display 9 takes — adds
  UPTO_DC6 to the UPTO_DC5 base) and
  `display/intel_display_power.c::get_allowed_dc_mask`
  (`max_dc` 2, DC9 only for GLK/BXT or ver >= 11, requested
  2 adds UPTO_DC6). The mask is UPTO_DC5 | UPTO_DC6 = 0x3,
  the allowed mask is UPTO_DC6 = 0x2, the target is DC6.
  The grounding's "UPTO_DC5 alone" recollection is wrong —
  it missed the `else` arm — and DC9 is NOT allowed on
  display 9 (the display-11 allowed mask DC9 | UPTO_DC6 =
  0xA does not carry over). This closes the grounding §17
  display-9 `max_dc` / allowed-DC-mask item. On that core
  sits the Gen9 `DC_off` service (`Gen9DcCore`), opted in
  with `narf.intel.gen9_dc=1` (default off, nothing written
  without it): probe holds Init (DC_STATE_DISABLE) until the
  Gen9 DMC loaded and the internal Pipe-A panel is owned;
  the Gen9 modeset, AUX, GMBUS (Gen9 LP only), hotplug, the
  external pass, the panel power-off and KMS sessions hold
  references, and the execlists GT holds `GT_IRQ` while
  unparked (`__gt_unpark`); the last release re-enters DC6
  (display 9, Wa Display #1183 first) or DC5 (Broxton /
  Gemini Lake) 17 ms later (100 ms after the GT parks),
  refused with power well 2 requested or on,
  the utility pin in PWM mode (DC6), a live external route,
  or a resident DMC program that no longer verifies. System
  suspend holds DC states off. On Gen9 LP with the display
  dark (every transcoder off, PW_2 not requested, no other
  holder) it then runs the rest of `bxt_display_core_uninit`
  (DBUF off, CDCLK bypass with the DE PLL off, the PW_1
  request dropped) and `bxt_enable_dc9` (PPS reset, DC9),
  and grants no reference until the resume; otherwise it
  stays in DC0. Resume exits DC9 (`bxt_disable_dc9`), runs
  the power half of the display-core init (PW_1 with its
  fuses, MISC IO on display 9 proper, DBUF) and reloads the
  resident program, releasing the Suspend reference only
  once it verifies.
- Forcewake (`intel_gpu_forcewake`): the Gen9 domain table
  is the three aggregate domains — render 0xA278, media
  0xA270, blitter 0xA188, acks 0x0D84 / 0x0D88 / 0x130044 —
  pinned as `GEN9_FW_DOMAINS` with the Gen9-named register
  constants. There are NO per-VDBOX/VEBOX sub-domains on
  Gen9 (those are Gen11+ only); Lane 3 reuses this table
  instead of duplicating it. The forcewake engine itself is
  generation-shared and unchanged.
- SAGV (`intel_gpu_gen9_sagv`): the Gen9 mechanism is the
  pcode 0x21 primitive from `display/skl_watermark.c` —
  `skl_sagv_enable` writes `GEN9_SAGV_ENABLE` (0x3) with
  no wait, `skl_sagv_disable` re-sends
  `GEN9_SAGV_DISABLE` (0x0) until the reply carries
  `GEN9_SAGV_IS_DISABLED` (0x1), inside a 51 ms budget
  (Linux's 1 ms base + 50 ms fallback). The display-11
  QGV-point mechanism (0xe) is a different mechanism and
  is not used here. Presence + status tracking
  (`I915_SAGV_ENABLED / DISABLED / NOT_CONTROLLED`,
  `intel_has_sagv`) and the pre/post-plane-update
  sequencing belong to the bandwidth-state caller; these
  are the primitives it will call.
- D3cold / runtime PM: no Gen9 arm was needed.
  `intel_gpu_d3cold` is generation-independent (root-port
  PME + ACPI `_PR3` + VRAM threshold) and
  `intel_gpu_runtime_power` carries no generation gating;
  both were verified, not changed.
- Remainder: the `pctx_corrupted` check
  (`GEN8_RC6_CTX_INFO` 0x8504, `gt/intel_gt_regs.h:544`) —
  Linux reads it at the tail of `intel_rc6_enable` and at
  the head of `intel_rc6_park`, and a zeroed register
  means the RC6 context was corrupted, disabling runtime
  power management. It is NOT modelled in `enable_gen9`:
  it needs the runtime-PM disable path to land on. The
  offset is recorded in `intel_gpu_rc6`'s header so that
  lane wires it without re-deriving it.

### 12.6 Gen9 modeset (Lane 5)

First light on the internal eDP panel, in Linux's SKL order
(CDCLK → DPLL → DDI pre-enable → transcoder/pipe/M-N → DBUF +
watermarks → plane → link training → DDI buffer → enables), on
the legacy modeset path (post-#2377 shape — the trained link is
returned on the legacy path). Lane 8 unblocked the Plan path
(`modeset_with_plan` / `modeset_mst_primary`) for external
outputs; see §12.7.

- DMC is REQUIRED (the §12.4 Q5 default, mirroring Gen12):
  the probe loads `i915/skl_dmc_ver1_27.bin` (Skylake) or
  `i915/kbl_dmc_ver1_04.bin` (Kaby Lake / Comet Lake) under the
  0x3000 per-program ceiling (`intel_gpu_gen9_dmc.rs`, in the
  Gen11 pattern; parse/load/verify machinery in
  `intel_gpu_dmc.rs` reused), records the install in an
  `AtomicBool`, and `modeset_display_family`'s Gen9 arm gates
  on it with `ModesetError::DmcUnavailable` before any register
  is touched. The probe itself continues either way — GT /
  execlists still bind — and only the display modeset refuses.
- Transcoder: the EDP transcoder binds the internal panel
  (timing base 0x6F000, conf base 0x7F000 — not aliased to the
  pipe block, unlike Gen12). Pipe A needs no power well
  (always-on); PG1 is a no-op (PW_1 is DMC-handled); Pipes B/C
  take PW_2 (idx 15); the DDI IO well is requested at
  pre-enable (A|E 1, B 2, C 3, D 4).
- CDCLK: the Gen9 program via LCPLL (`intel_gpu_gen9_cdclk.rs`),
  VCO 8100, pcode pre/post voltage notifies (cmd 0x7); for the
  1080p60 panel mode (148.5 MHz, floor 74.25 MHz) the rung is
  337.5 MHz (freq_sel 2, decimal 673).
- DPLL: DPLL0 for the eDP panel, DPLL1 otherwise
  (`dpll_pool`); `DPLL_CTRL1` carries OVERRIDE + link rate,
  `DPLL_CTRL2` routes the port, and there is no DPCLKA or TGL
  CFGCR0 on SKL. `modeset_hdmi` had refused Gen9 outright
  (it would otherwise have run the Gen12
  `program_dpll_coeffs` writes on SKL); Lane 8 added the
  Gen9 HDMI branch (§12.7).
- Training: the whole `DDI_BUF_TRANS` table is programmed at
  pre-enable, then each training iteration applies the sink's
  requested level via lane 0's level only (`preset_index` +
  `skl_ddi_set_iboost` at that level + `DDI_BUF_TRANS_SELECT`
  into `DDI_BUF_CTL` bits 27:24), and a dirty pattern-1
  retunes the DPLL and re-prepares. The sink trains TPS1 →
  TPS3 → off; `DP_TP_CTL` ends NORMAL (0x80040300).
- Watermarks: the 8 SKL levels over the full 892-block DBUF
  (TRANS 0 per WaDisableTWM), `PLANE_BUF_CFG` = the whole
  DBUF, DBUF slice S1 power-requested.
- Plane admission reuses the SKL rule (256 KiB surface
  alignment, 32 KiB stride cap) — `gen11_alignment()` /
  `gen11_max_stride()` renamed to `skl_alignment()` /
  `skl_max_stride()` with the Gen11 call sites updated;
  `gen12_alignment()` / `gen12_max_stride()` stay Gen12-only.
- PSR is excluded on Gen9 (the `PsrLayout::from_generation`
  fallback would program the TigerLake table on SKL); the
  panel runs plain eDP. The VRR placeholder maps Skylake to
  the Gen12 arm for exhaustiveness only — no VRR timings can
  be computed (range is `None`) and no VRR path can fire.
- Panel fitting: `Modeset::set_gen9_panel_fit` runs the
  display-9 pipe scaler (`intel_gpu_xelpg_scaler::plan_display9`)
  with the `display/skl_scaler.c` limits (Linux 7.4-rc2): max
  src 4096×4096, max dst 4096×4096; `calculate_max_scale`
  non-YUV 3.0× both axes (0x30000−1), YUV semiplanar 2.0×
  (0x20000−1); NV12 scaler mode `SKL_PS_SCALER_MODE_NV12`.
- VBT boost levels are unplumbed caller inputs (Lane 4
  remainder): `dp_boost` is false for first light and the
  VBT boost level is not consumed.

### 12.7 Gen9 external outputs (Lane 8)

External DP (DDI B–E, Plan path) + HDMI + IRQ routing + SPT
backlight, fixture-validated, silicon untested. The Gen9
programme's last lane; `external_display_supported()` and
`backlight_supported()` flip for `Generation::Skylake` here.

- Port map (`intel_gpu_gen9_ddi.rs`, `skl_display`):
  port A is the eDP panel, ports B–E are DP/HDMI, F+ do not
  exist. Pipes A/B/C, transcoders A/B/C + EDP, DBUF 896−4
  blocks, slice S1 only. The port-kind, DPLL-pool and SKU
  tests pin the map across Skylake/KabyLake/CometLake (the
  external paths key off `Gen9Platform`, not PCI IDs).
- DP training reuse: Lane 5's training loop is port-agnostic
  (`is_edp = ddi == Ddi::A` → `Output::Dp` for external) —
  no second training loop was written. The only thing that
  blocked external DP was the Plan-path backstop in
  `modeset_impl`; removing it unblocked `modeset_with_plan`
  and `modeset_mst_primary` (same `LinkStep::Plan`).
  Everything else already dispatched Gen9 (DPLL, DPCLKA
  routing, watermarks, DBUF, power wells, M/N, FUNC_CTL).
- DPLL arbitration (named remainder): Linux `skl_get_dpll`
  gives eDP DPLL0 only and every other output the first
  free of DPLL1/2/3 (occupancy-based). NARF has no
  cross-run occupancy tracking, so the modeset takes the
  first of the pool — DPLL1 for every external output —
  and `program_dpclka_routing` makes the same pick, so the
  DPLL program and the clock routing agree. Two
  simultaneous external outputs would both take DPLL1;
  occupancy tracking is the follow-up.
- HDMI (`modeset_hdmi` Gen9 branch): the TGL
  `hdmi_wrpll_coeffs` search is skipped for Gen9; the SKL
  WRPLL row comes from `hdmi_state` under the fixed 24 MHz
  reference (`REFCLK_KHZ` — Lane 4's CDCLK hardcodes ref
  24000, not the DSSM strap). For 1080p60 (148.5 MHz): the
  winning divider is 12, DCO 371 + 0x2000, CFGCR1
  0x80400173, CFGCR2 0x3A5. Levels are the SKL HDMI table's
  default entry (index 8) at BUF_TRANS index 9 plus the
  I_boost for that entry — Linux `hsw_set_signal_levels`
  runs `skl_ddi_set_iboost` for HDMI, then returns ("HDMI
  ignores the rest"). Wa #1143 (HDMI-only,
  `display/intel_ddi.c:3455`): pulse
  `DDI_TRAINING_OVERRIDE_ENABLE | VALUE` in the port's
  transcoder chicken register (set, posting read, 1 µs,
  clear; port E uses bits 17/16 of `CHICKEN_TRANS_A`).
- DMC gate: the Q5 default (DMC REQUIRED) now fires at the
  top of `modeset_impl` on every entry (legacy, plan,
  trained), not only the panel entry
  (`modeset_display_family` gates the panel path), and at
  the top of `modeset_hdmi` (which bypasses `modeset_impl`
  entirely) — both before any register is touched.
- IRQ routing (`intel_gpu_gen9_irq.rs`): the Gen9 display +
  GT interrupt model, grounded register-by-register against
  `display/intel_display_irq.c`, `gt/intel_gt_irq.c`,
  `i915_irq.c` (Linux 7.4-rc2) — this closes the §12.4
  interrupt-routing item. `GEN8_MASTER_IRQ` 0x44200
  (CONTROL bit 31; the Gen11 HPD bit 21 in the same address
  does not exist on Gen9), the DE block (0x44000 summary,
  0x44400 pipes, 0x44440 port, 0x44460 misc, 0x444e0 PCU),
  the four GT banks (0x44300 + 0x10 per bank), and the
  reset (`gen2_irq_reset` shape) / post-install
  (bank 2 stays IER 0 / IMR all-ones; PM/RPS + GuC enable on
  demand) / decode / W1C-ack primitives, with fixtures
  pinning the addresses, the write sequences, the master
  decode split (GT banks vs display), the port hotplug bits
  (3 + pin − A) and the Gen9 AUX mask (A + B/C/D), and a
  negative control that the xe-era 0x190000 block is never
  touched. Verification method: each constant and sequence
  was transcribed from the named Linux source and pinned by
  a fixture that asserts the exact register write sequence
  — the module is register-level routing only. Live
  IRQ-handler wiring is a named remainder (no
  interrupt-domain registration exists in this crate yet).
- HPD / external sessions: the session layer
  (`enable_external_hpd`, `poll_external_hpd`, `dp_connect` /
  `hdmi_connect` / `mst_connect`) admits Gen9 through
  `SourceFamily::Gen9`, with the SPT-class south hotplug bank
  (`HpdBank::Spt`, polled) and the SPT DDC pins, and MST runs
  on the same sources. `intel_gpu_gen9_irq` has no caller.
- Backlight: Skylake drives the SPT PWM block
  (`intel_bl.rs` `PwmLayout::Spt`: max = `BLC_PWM_PCH_CTL2`
  0xC8254 >> 16, duty RMW into CTL2's low 16 bits,
  `lpt_set_backlight` / `lpt_get_backlight`); the probe
  branches to `install_spt` for Skylake and keeps the BXT
  install for Gen11/Gen12. `SPT_PWM_GRANULARITY` (bit 0 of
  `SOUTH_CHICKEN1`, alternate increment) is not modeled —
  the device preserves the firmware period and never
  converts Hz→PWM; a future VBT-plumbed backlight can set
  it at enable time per `lpt_enable_backlight`. The SPT
  enable sequence (CTL1 enable) likewise belongs to a
  future backlight-enable step.
- Fixtures: `smoke_gen9_external_dp_ddi_b_full_run` and
  `smoke_gen9_hdmi_ddi_b_full_run` (DDI B / Pipe A / HBR2
  x4 / 1080p60) assert the full register image — CDCLK
  337.5 MHz rung, DPLL_CTRL1/2, DDI-IO-B power well,
  watermarks, BUF_CFG, the SKL DP/HDMI tables at the
  port-B BUF_TRANS block, I_boost, DDI_BUF_CTL, DP_TP_CTL,
  FUNC_CTL, the Wa #1143 pulse, and the absence of TGL
  registers, DDI A, and the EDP transcoder — plus ten
  `intel_gpu_gen9_irq` fixtures and the SPT round-trip.
  Two Lane 5 panel-test assertions were corrected in this
  lane (both never executed: host test execution was
  deferred): DDI_BUF_CTL's last write is 0x84000086, not
  0x84000006 — the IDLE bit the fixture serves on readback
  survives the enable RMW — and the PLANE_WM stride is 4,
  not 8 (the Gen11 full-run test pins the same stride).

## 13. Suspend/resume + D-states (Stage 5 — `intel_gpu_pm`, #1015)

System power for the GPU: the device-PM quiesce/D3/restore
conversation, honest PCI D-state reporting (the DRM card's
`power_state()` was a hardcoded `"D0"`), and the S4 state
hook that carries the configuration through the suspend
service's sealed image. Compiled only under the gpu crate's
`intel` feature. Sources: PCI Bus Power Management
Interface Specification rev 1.2 §3.2.4 (PMCSR) and §5.4
(10 ms D3 settle), as implemented by `narf_bus::pci`
(`power_state` / `set_power_state`, Linux
`pci_raw_set_power_state` semantics: preserve all PMCSR
fields but PowerState, write 0 to the RW1C PME_Status
bit); the power-suspend design (`SuspendStateHook`
contract, §5.2 rule 1–5) from `power/specification/
spec.md` §3.3; §§11–12 of this document for the forcewake
and RC6/DMC conversations composed here.

### 13.1 Registration and census

At probe success (Gen12-class parts only — the predicate
is `region_generation() == Some(RegionGeneration::Gen12)`;
Xe-LPG has a region map and display engine since #1016 but
no modelled forcewake/RC6/DMC programming, so it stays
excluded), probe
retains its `(BusDevice, Cap)` in the PM module and
registers, both under the name `"intel-gpu"`: a
`device_pm` ops pair (S3 fan-out) and a `SuspendStateHook`
(S4 seal/unseal). Registration is a probe-time call, not
an initcall: **no new initcalls, census unchanged.**
Runtime modesets (future lanes) must call
`note_active_mode` when they change the active mode, or
resume re-lights the stale one.

### 13.2 Snapshot format (`PmSnapshot::to_bytes`)

Header (18 bytes): magic `"NARFIPM1"`, version u16 = 1,
total length u32, payload length u32. Payload: seq u64;
flags u8 (bit0 has-mode, bit1 has-scanout, bit2
RC6-enabled, bit3 DMC-present); DC target field bits u8;
pre-suspend D-state bits u8; DMC program mask u8 (bit i =
`DmcId::ALL[i]` present); RC6 residency raw counter u32;
then, if has-mode, the `Mode` (pixel clock u32, eight
timing u16s in struct order, sync-polarity u8); then, if
has-scanout, width/height/stride/gtt_offset u32s and
phys_base u64. Trailer: CRC-32/ISO-HDLC (check value
0xCBF43926 for `"123456789"`) over all preceding bytes.
Parsing is fail-closed: magic, version, exact length
agreement, CRC, field sanity (DC bits ≤ 2, D-state bits
≤ 3, nonzero mode geometry with totals ≥ actives), and no
trailing payload — any failure refuses the whole snapshot
and nothing from it is applied. The S4 copy is additionally
AEAD-sealed by the suspend service; the CRC guards the
in-RAM S3 copy and the framing, not an attacker.

### 13.3 Sequences and failure discipline

Suspend: close the RCS submission gate (new submissions
refuse with `SubmitError::Suspended`) → drain completions
until the engine is idle (budget: 100 000 polls — a count,
not a deadline) → snapshot → forcewake sanitize → park
RC6 if enabled (the drain proved zero submission-scoped
holds exist, so park's `DomainsHeld` refusal cannot fire)
→ PMCSR D3hot + 10 ms settle. A drain that never converges
refuses with `Busy` before any power register is touched:
gate reopened, no snapshot, device fully live. Any later
failure before the D3 write rolls back the same way (a
failed D3 write additionally unparks).

Resume: PMCSR D0 + settle → **readback must report D0**,
else the device is named `Degraded(HardwareRestore)` and
the gate stays closed (a retry from that phase is legal)
→ forcewake sanitize → DMC reload + `verify_loaded` + DC
target restore → RC6 re-enable if the snapshot had it →
display re-light: `relight_display` allocates a *fresh*
scanout and re-runs the real modeset at the snapshot mode
(GGTT PTEs do not survive D3; the pre-suspend surface is
never restored in place). The modeset's EDID readback may
apply the panel's preferred mode instead of the saved
fallback — the same behaviour as probe takeover; the
returned scanout follows the applied mode. Each subsystem
restore is attempted even if an earlier one degrades, and
the phase names the first missing piece:
`Degraded(SnapshotInvalid | UnverifiedRestore |
HardwareRestore | DisplayRelight | DmcRestore)`. With no
trusted snapshot, resume re-establishes from driver-owned
state (and reconciles the software RC6 flag via the
disable conversation — D3 reset the hardware underneath
it).

The hook is **not critical**: `seal` serializes the
snapshot from the device suspend (the service runs the
seal fan-out after device quiesce); `unseal` records
Verified/Missing/Invalid; `reconcile_after_unseal` then
acts — a verified blob replaces the restore source
pre-resume or re-applies its display state post-resume, a
missing/invalid blob revokes the RAM snapshot's trust
(pre-resume) or forces re-establishment from driver state
(post-resume, named `Degraded(UnverifiedRestore)`). All
GPU state is reconstructible, so a failed blob must never
abort a resume (design §5.2 rule 4 reserves criticality
for irreconstructible state).

### 13.4 Named remainders

DMC firmware sourcing: `register_dmc_firmware` is the
seam (parse-validated at registration, wildcard stepping
selection — probe's `ChipInfo` carries no stepping
readout in this tree). The probe-time Gen12, Gen11 and Gen9
DMC loads (`intel_gpu_gen12_dmc`, `intel_gpu_gen11_dmc`,
`intel_gpu_gen9_dmc`) register their resident blob there, so
resume reloads it. Display 14 does
not use this core: its container is acquired, loaded and
restored across suspend by the DC service (§12.1), next to
the GT runtime owner that handles its system PM. RC6 enable-at-probe is
likewise a wiring step: the PM core owns the `Rc6`
lifecycle (snapshotted posture, park, re-enable), and
today nothing enables RC6 at probe, so in production the
snapshot's RC6 bit is currently always off. D3cold is not
used. The PCI runtime layer has a `PciPlatformPm` seam, but no
provider exists: there is no `_PR3` evaluation and no
root-port PM read authority. `d3cold::evaluate` names the
missing piece (§20, GT runtime power), and the link stays up
and config survives. Runtime D3hot of the GuC owners, including
integrated functions whose panel is dark, is described in §20.
PSR/DC-state runtime policy and S0ix are out of scope.

## 14. External DisplayPort, full single-stream (lane Q4 — `intel_gpu_dp`, #1092)

The external-DP path for combo DDIs A/B/C, Gen12. Compiled
only under the gpu crate's `intel` feature. Sources: VESA
DisplayPort 1.4a (§2.7 AUX, §2.7.6 I²C-over-AUX, §3.5 link
training, DPCD receiver-capability field), TGL PRM Vol. 11
(PLL table, HPD block) and Vol. 12 (DDI, audio), CEA-861-D
§7.5 (ELD).

Public interface:

- `probe_sink(mmio, ddi) -> DpSinkProbe` — the AUX
  conversation: DPCD capabilities, the *complete* EDID (base +
  extension blocks), and link negotiation for the preferred
  mode. No display registers are touched beyond AUX.
- `activate(mmio, probe, fb) -> DpConnection` — modeset at
  the negotiated plan (`Modeset::modeset_with_plan`), then
  display-audio publication. `connect` composes the two.
- `disconnect(mmio, conn)` — audio disable + sink clear, then
  pipeline teardown. `retrain(mmio, conn, fb)` answers an
  IRQ_HPD short pulse: the connection stands if every trained
  lane still reports CR_DONE, else a fresh connect runs.
- `HpdMonitor` / `poll_hpd_event` — observed TGP/ADP south-display
  SDE registers (ISR0xc4000, IMR0xc4004, IIR0xc4008, IER0xc400c),
  SHOTPLUG0xc4030 and observed shared filter0xc4038=F8. Physical
  combo B is qualified only on TGL/ADL-P/N; ADL-S and combo C refuse.
  Setup masks before IER and establishes fresh owned IIR/SHOT status,
  preserving foreign W1C state. Later source LONG+low indicates removal;
  short/unknown/pre-IIR low retains known-connected state. Current GPU
  authority and unchanged observed PCH facts gate every pass. The runtime
  services an already-retained SST owner; new-output discovery and live
  retraining remain separate. Native pipe/surface settling precedes
  publication and checked local stop precedes serial-matched withdrawal.

Two seams are defined here for named consumers:

- **Shared link-training core** —
  `dp_link_training::{read_caps, negotiate, train_negotiated}`
  (with `DpcdCaps`, `SourceCaps`, `NegotiatedLink`): the
  vendor-neutral caps + negotiation + training composition
  over `dp_aux::AuxChannel`. Negotiation policy: lanes first
  (largest mutually supported of 4/2/1), then the lowest rate
  whose 8b/10b payload covers the stream demand, capped by
  both sides; an uncoverable demand settles at the mutual
  ceiling with `over_budget` reported. **Thunderbolt lane 3
  (#1095) consumes this seam** over tunnelled AUX and must not
  re-implement it.
- **Shared display-audio sink** —
  `narf_drivers_sound::display_audio`: `build_eld` turns a
  complete EDID into the CEA-861 ELD publication (layout
  field-checked against the HDA codec's own ELD parser);
  `publish_display_audio` / `clear_display_audio` /
  `current_display_audio` are the registry. **HDMI-full
  (#1019) consumes this seam** as second publisher (same sink
  id per physical connector: DDI index + 1). The Intel codec
  side (`intel_gpu_audio`: AUD_CONFIG DP timestamp update,
  AUD_PIN_ELD_CP_VLD output-enable / ELD-valid sequencing per
  `hsw_audio_codec_enable/disable`) raises ELD_VALID only
  after the ELD is published in the sink.

Modeset plan path (`Modeset::modeset_with_plan`): the DPLL
is programmed at the negotiated rate, M/N and the
`TRANS_DDI_FUNC_CTL` port width carry the planned rate/lanes,
and if the fallback ladder settles elsewhere the DPLL, M/N and
port width are reprogrammed to the trained configuration before
the DDI buffer enables (the combo-PHY levels need no such
reprogramming — the training callback already re-selected the
table for the settled rate). On the combo path the DPLL part
of that reprogramming already happened mid-training: the
callback retunes the DPLL when the fallback retry opens (see
§7), so the post-training re-program rewrites the same rate.
The legacy eDP path uses the same combo callback, so it gets
the mid-training retune too — previously a legacy fallback
settled at the wrong clock, since the post-training DPLL
re-program above only runs when a plan was given.

Invariants:

- Every DPCD read on the wire requests exactly the byte count
  its caller waits for. (Found defect, fixed in this lane:
  `dp_aux::AuxChannel::dpcd_read` and the `dp_edid` chunk
  reads passed an empty length placeholder, so over the Intel
  MMIO transport every multi-byte read failed reply-length
  decode and EDID readback silently fell back to the
  hardcoded mode. The per-address test stubs that ignored the
  request length masked it; the composed transport+sink
  fixtures here are the regression pin.)
- EDID-over-AUX is one I²C read transaction per 128-byte
  block: offset write, then 16-byte bursts with MOT clear on
  all but the final burst (MOT set = STOP). Extension blocks
  are fetched per the base block's byte 126; blocks past the
  first 256-byte segment would need the I²C 0x30 segment
  pointer, which is not driven (the CTA block is extension 1).
- The plan path programs the DPLL at the negotiated rate
  under the DSSM-selected reference family (lane Q6, #1024 —
  `decode_refclk_family` + `combo_coeffs(rate, family)`), the
  same resolver the legacy path uses; both PRM families
  (19.2/38.4 MHz and 24 MHz) are fixture-pinned there.
- Audio is published only when the sink's CTA extension
  carries at least one SAD; a sink without audio gets video
  only, and disconnect always clears the publication before
  the pipeline comes down.

Deliberate remainders (MST and multi-pipe are §16, Xe-LPG §17):
Type-C HPD via the GEN11 DE HPD block
(the Alt-Mode bridge's DDIs), DSC/FEC, and the HPD IRQ
handler itself (interrupt enables are programmed; the
session is poll-driven until an IRQ consumer lands).

## 15. External HDMI, full (lane Q5 — `intel_gpu_hdmi`, #1019)

The external-HDMI path for combo DDIs, Gen12. Compiled
only under the gpu crate's `intel` feature. Sources: HDMI
1.4 §5.3.5 and CTA-861 infoframe packing (as implemented
by Linux `drivers/video/hdmi.c`), HDMI 2.0 §10 (SCDC; the
register map as carried by `drm_scdc_helper.h`), TGL PRM
Vol. 2c (TRANS_DDI_FUNC_CTL HDMI bits), Vol. 11 (WRPLL —
the `cnl_ddi_calculate_wrpll` search i915 uses for HDMI on
CNL and ICL+), Vol. 12 (DIP banks, AUD_CONFIG), CEA-861-D
§7.5 (ELD, via the §14 sink).

Public interface:

- `probe_sink(mmio, ddi, ddc) -> HdmiSinkProbe` — the complete
  EDID over DDC on the VBT or default pin (`ddc`:
  `Gen12DdcOverrides`), the preferred mode, the HDMI Forum VSDB
  capabilities, and whether the mode's character rate
  demands scrambling. No display registers are touched.
- `activate(mmio, probe, fb) -> HdmiConnection` — SCDC
  configuration where required, the WRPLL modeset
  (`Modeset::modeset_hdmi`), the AVI infoframe, then
  display-audio publication. `connect` composes the two.
- `disconnect(mmio, conn)` — audio disable + sink clear,
  DIP disable, SCDC reset for a scrambled stream
  (`intel_ddi_disable_hdmi`), pipeline teardown.

DDC runs over the shared **GMBUS transport**
(`intel_gpu_gmbus::GmbusBus`, `do_gmbus_xfer`). Each EDID block
is `drm_do_probe_ddc_edid`'s transfer: offset write and read as
one index transfer, and for blocks 2 and 3 the E-DDC segment
pointer chained ahead of it by repeated START, so the pointer
reaches the read before the single STOP (`read_edid_eddc`, up
to base + 3 extensions). SCDC registers are `drm_scdc_readb`
(index transfer) and `drm_scdc_writeb`. This replaced an older
engine that ran each program as one STOP-cycle transfer and then
waited for bus idle, wrote byte indices to GMBUS5 without
`GMBUS_2BYTE_INDEX_EN` (so they were not indexed), and checked
the sink's scrambler status before scrambled data flowed.

The DDC pin is the VBT's when the board's VBT declares an HDMI
connector on the DDI (`Gen12DdcOverrides`: `intel_hdmi_ddc_pin`
through `map_ddc_pin`'s icp/adls/adlp maps, validated and
unclaimed), otherwise the family's Linux default
(`intel_gmbus::gen12_ddc_pin`, b90c984d
`intel_hdmi_default_ddc_pin`): Tiger Lake and Alder Lake P/N
use DDI A/B = GMBUS pin 1/2 and TCn = 8 + n; Alder Lake S
uses DDI A = 1 and TC1..TC4 = 9..12. A DDI the platform
lacks (DDI C, ADL-S DDI B, DDI H off Tiger Lake) refuses with
`NoPinPair` before any access. The earlier DDI A..F = 2..7
encoding selected the neighbouring pin pair and was
corrected in 2026-11.

Character-rate rule (HDMI 2.0 §10.4): at 8 bpc the TMDS
character rate of a mode is its pixel clock. Above
340 Mcsc the stream requires SCDC scrambling and the 1/40
TMDS bit-clock ratio, plus both TRANS_DDI_FUNC_CTL HDMI
bits (Scrambling Enabled bit 0, High TMDS Char Rate
bit 4); the PLL still runs at 5× the character rate (the
1/40 ratio divides the bit clock, not the character-rate
clock). At or below 340 Mcsc the sink is not touched over
SCDC at all. A >340 Mcsc mode against a sink whose HF-VSDB
does not declare SCDC is refused with
`ScramblingUnsupported`, never silently degraded.

SCDC sequence (`configure_scdc`): refuse unless the
HF-VSDB declares SCDC_Present; then
`intel_hdmi_handle_sink_scrambling`
(`handle_sink_scrambling`): read-modify-write TMDS_CONFIG
(0x20) bit 1 (`drm_scdc_set_high_tmds_clock_ratio`), wait
at least 1 ms, then read-modify-write bit 0
(`drm_scdc_set_scrambling`). Configuration runs before the
modeset binds the transcoder (Linux runs it before the DDI
buffer enable; both precede any TMDS data). SCRAMBLER_STATUS
(0x21) is read only after the stream runs and recorded as
`HdmiConnection::scrambler_status`; like Linux, it does not
gate the connect. Disconnect resets the ratio and scrambling
before the pipeline comes down. The admission rule stays
narrower than Linux's: at or below 340 Mcsc SCDC is never
touched, where Linux also writes a scrambling-capable sink's
TMDS_CONFIG.

Clocking: HDMI rates do not come from the fixed DP PLL
rows — `intel_gpu_pll::hdmi_wrpll_coeffs` runs the WRPLL
search (AFE = 5× TMDS clock; DCO window 7 998–10 000 MHz;
the divider list and P/Q/K decomposition transcribed from
`cnl_ddi_calculate_wrpll` / `cnl_wrpll_get_multipliers`;
38.4 MHz reference treated as 19.2 per
`cnl_hdmi_pll_ref_clock`), under the reference family
decoded from the DSSM strap (lane Q6, #1024), as on the DP
path. Rows are fixture-pinned with an
independent decode check (DCO / (P·Q·K) must reproduce
exactly 5× the TMDS clock). `Modeset::modeset_hdmi` omits
the DP-only steps: no M/N, no link training; the combo-PHY
HDMI default level (ICL HDMI table entry 6) is programmed
before the DDI buffer enables, and the DDI buffer enables at
the HDMI-fixed 4-lane width.

Infoframes: AVI (type 0x82, v2, 13 data bytes) and audio
(type 0x84, v1, 10 data bytes) packed per HDMI 1.4 §5.3.5
with the checksum byte making the whole frame sum to
0 mod 256; both pinned byte-for-byte in fixtures. The VIC
comes from the mode's geometry (a small table; exact
timings still govern the modeset — 720×480 pins the 4:3
VIC 2 because the mode shape carries no pixel aspect).
The AVI frame is written through the HSW+ video DIP:
CTL enable bit cleared, the 32-byte DIP image written to
the AVI data bank (the frame's checksum slot is a 1-byte
hardware ECC hole at buffer position 3), enable set,
posting read. The audio infoframe is *not* DIP-programmed
— this hardware has no audio DIP bank; the HDA codec
synthesises it from the published ELD, and the packed
frame rides the connection for that consumer.

Audio consumes the §14 **shared display-audio sink** as
second publisher (`DisplayConnector::Hdmi`; same sink id
per physical connector — DDI index + 1 — because a
connector is either DP or HDMI at a time). The codec side
is the HDMI branch of `intel_gpu_audio`: AUD_CONFIG
carries the PRM pixel-clock code for the TMDS clock and
latches with N_PROG_ENABLE only (no DP timestamp mode, no
N_VALUE_INDEX — the disable path conditions that bit on
the old configuration being DP, so the HDMI disable omits
it too). Publication order matches §14: ELD into the sink
first, codec enable, then ELD_VALID. The cross-vendor
display-audio story is tracked in #778 (AMD), referenced
not closed by this lane.

Physical HPD follows the source-qualified SDE/SHOT contract in §14;
HDMI sinks answer DDC and DP sinks answer AUX. The legacy connect dispatch
may try DP then HDMI, but the incremental runtime drain owns only retained
SST DP. HDMI/MST retain their BAR/graph and return Busy for PM/reset drain
until their own full source stop protocols are qualified. Short pulses do
not constitute unplug proof or qualify live retraining.

Invariants:

- A ≤340 Mcsc connect produces zero SCDC-slave traffic
  (fixture-asserted over the recorded GMBUS programs).
- SCDC writes precede the first TRANS_DDI_FUNC_CTL write,
  and SCRAMBLER_STATUS is read only after the DDI buffer is
  enabled (fixture-asserted over the recorded write log).
- Every DDC transfer ends in one STOP; an E-DDC segment write
  is followed by its EDID read with no STOP in between.
- The modeset's CFGCR0/CFGCR1 writes for a mode equal the
  WRPLL fixture rows for that TMDS clock.
- Disconnect clears the ELD publication before the
  pipeline comes down, and clears the DDI buffer last.

Fixtures: a GMBUS sink model (EDID store + SCDC register
file decoding the GMBUS1 program fields itself, wait phase
only for CYCLE_WAIT programs, E-DDC segment reset on STOP)
exercising 1080p connect with no SCDC traffic, 4K60 connect
with the ratio-then-scrambling RMW + post-stream status +
func-ctl bit pins, 4K60 refused without SCDC, an unlocked
scrambler reported after the stream without failing the
connect, the index cycle and GMBUS5 enable bit, sink NACK,
4-block EDID over chained E-DDC segment writes, HF-VSDB
parsing past a decoy HDMI Licensing VSDB, infoframe byte
pins, and disconnect teardown order.

DVI sinks, deep colour (10/12 bpc) and YCbCr 4:2:0 on display 11/12
(Y420VDB/Y420CMDB, `intel_hdmi_compute_output_format`, the 1:1 pipe
scaler, the BT.709 output CSC) are implemented with native fixtures;
display 14 and 20 take 4:2:0 in `intel_gpu_xelpg_hdmi`, and HDMI 2.1
FRL runs through a DP PCON (i915 has no native FRL). HDCP is §20,
behind `narf.intel.hdcp=1`. Deliberate remainder: Type-C HDMI alt mode.

## 16. Multi-pipe display + DP MST (lane Q11 — `intel_gpu_multipipe`, `intel_gpu_mst`, #1017)

Supersedes §14's "DP MST and multi-pipe" remainder. Compiled
only under the gpu crate's `intel` feature. Sources: VESA
DisplayPort 1.4a (§2.7.6 sideband messaging, §2.11 MST
payload management, PBN accounting), TGL PRM Vol. 11 (DPLL,
power wells), Vol. 12 (DBUF allocation, transcoder/DDI),
Vol. 14 (plane watermarks). The sideband codec and topology
manager are the vendor-neutral `dp_mst` / `dp_mst_mgr`
modules (shared with the AMD MST consumer); this lane adds
the Intel transport adapter, the pipe/DBUF substrate, and
the session composition. No new initcalls: sessions ride
the §14 HPD/initcall flow.

### Multi-pipe substrate (`intel_gpu_multipipe`, `Modeset::for_pipe`)

- **Pipe ownership.** Pipes A–C are allocatable; Pipe D is
  refused (no power well in the Gen12 orchestrator map).
  `PipeAllocator` hands a pipe to exactly one
  `PipeOwner { ddi, used_for }` (`InternalPanel`,
  `ExternalSst`, `ExternalMst`, `AltModeBridge`). Claims are
  idempotent for the same owner, owner-only on release; the
  process-global registry (`PIPE_ALLOCATOR`) is the single
  arbiter between the internal panel, SST sessions, MST
  streams, and Alt-Mode bridge sessions. Probe claims Pipe A
  for the internal panel when takeover produced a mode.
- **Per-pipe modeset.** `Modeset::for_pipe(pipe)` binds the
  pipe, its same-index transcoder, its power well (PG2/PG3/
  PG4 for pipes A/B/C — the i915 ICL+ domain map), and its
  DPLL index (DDI A→DPLL0, B→DPLL1, C→DPLL2; TC DDIs D–H
  share DPLL0 historically — TC PHY PLL programming is a
  named remainder). `Modeset::new` is `for_pipe(Pipe::A)`
  and the single-pipe register sequence is byte-identical
  to the pre-lane orchestrator.
- **Per-pipe GGTT scanout windows.** Windows are strided
  32 MiB apart from `SCANOUT_GTT_OFFSET_PIPE_A`
  (A 0x1000000, B 0x3000000, C 0x5000000) via
  `alloc_contiguous_scanout_at`, so concurrent sessions
  never share a scanout block.
- **DBUF partition.** The partition covers 1024 blocks
  (slice S1; PRM Vol. 12: S1 alone = 1024, S1+S2 = 2048).
  Q6 (#1024) now powers both slices at modeset, but the
  multi-pipe split stays within S1 — using S2 and the PRM
  slice-assignment table are named remainders. With ≥2
  active pipes the coordinator
  (`reprogram_dbuf_shares`) partitions the 1024 blocks into
  contiguous equal shares over the sorted active set and
  reprograms each pipe's PLANE_BUF_CFG / PLANE_WM level 0
  from its share. A lone pipe keeps the preboot programming
  untouched; when the active set drops back to one pipe the
  survivor keeps its last share until its next modeset.
  A pipe with an explicit share is programmed in the
  preboot shape at its share's size; a lone pipe (no share)
  runs Q6 (#1024)'s latency-based watermark algorithm over
  the whole DDB on its own pipe, falling back to the preboot
  values as before.

### MST session (`intel_gpu_mst`)

- **Transport.** `IntelMstAux` implements the manager's
  `MstAux` trait over `IntelAux`, chunking every transfer
  at the 16-byte native AUX limit. `MstLink` owns one DDI's
  `dp_mst_mgr::Manager`, the negotiated caps, the trained
  link, a per-hop available-PBN ledger seeded from
  ENUM_PATH_RESOURCES at probe, and the live stream set.
- **Stream lifecycle.** `add_stream` refuses locally —
  before any modeset or allocation traffic — when the
  stream's PBN exceeds any hop's ledger availability
  (`InsufficientBandwidth { needed_pbn, available_pbn }`).
  The primary stream trains the link via
  `Modeset::modeset_mst_primary` (TRANS_DDI_FUNC_CTL DP-MST
  mode); secondary streams reuse the trained link via
  `modeset_mst_secondary` and never touch the shared link
  blocks (DPLL, DPCLKA, BUF_TRANS, training, DDI buffer).
  Payload commit order per stream: source payload-table
  entry (`write_payload` part 1), then ALLOCATE_PAYLOAD to
  the end branch (part 2); a partial grant (granted ≠
  requested) is a refusal. Any failure rolls back in
  reverse — payload deallocation and table clear, then
  modeset teardown (full teardown + untrain only when no
  stream survives; otherwise a pipe-scoped
  `teardown_stream`) — so a refused or failed stream never
  disturbs a live one. `remove_stream` deallocates,
  clears the table entry, tears down, credits the ledger,
  and compacts surviving streams' table slots back to
  dense (slot 0 is the MTP header; VCPIs are 1..=63).
- **Notifications.** Up requests drained on the HPD
  RetrainRequired path surface as `MstEvent`s;
  RESOURCE_STATUS_NOTIFY additionally updates the ledger
  entry for the notifying branch's port.
- **Failure discipline.** Sideband timeouts, NAKs, and
  malformed replies are the manager's typed errors,
  wrapped unchanged (`MstError::Mgr`); AUX failures stay
  `MstError::Aux`. A DDI whose sink lacks MST capability
  (DPCD rev < 1.2 or MSTM_CAP clear) falls back to the §14
  SST session. An HPD disconnect tears streams down in
  reverse order, disconnects the manager, and releases
  the pipes.

Named remainders: per-stream MST display audio, DSC/FEC
over MST, TC PHY PLL programming for DDI D–H, DBUF slice
S2, fb-console publication staying single-slot (last HPD
wins; per-pipe publication is a console-layer decision),
and the Alt-Mode bridge holding its pipe claim for the
session lifetime (the bridge trait has no exit hook).
## 17. Xe-LPG display — Meteor Lake (lane Q10, #1016)

Meteor Lake's display engine is Xe-LPG, a different IP block
from Gen12's Xe-LP. Before this lane, probe identified MTL SKUs
but the takeover path ran the Gen12 sequence at them; lane 1
gated MTL/PTL to identify-and-skip, and this lane implements
the real Xe-LPG path. Sources are the Meteor Lake display PRM
(§2) as implemented by i915 — `intel_cx0_phy_regs.h`,
`intel_cx0_phy.c`, `intel_cdclk.c`, `intel_ddi.c`,
`intel_display_power_map.c` — never the Gen12 code being
diverged from.

Structure: dispatch is by generation at the single takeover
entry (`intel_gpu_modeset::takeover_display`). Gen12 silicon
runs the Gen12 orchestrator byte-identically; Meteor Lake runs
`intel_gpu_modeset_xelpg::XeLpgModeset`. The pipe / transcoder /
plane register block did not move, so both orchestrators build
those programs from the shared `intel_gpu_pipes` codecs.

### 10.1 Port / PHY map

| Port | BAR0 block | PHY | TRANS_CLK_SEL idx | TRANS_DDI_FUNC_CTL idx | AUX well (AUX2) |
| ---- | ---------- | --- | ----------------- | ---------------------- | --------------- |
| DDI A | 0x64000 | C10 | 0 | 0 | AUX CTL 0x64010 bit 19 |
| DDI B | 0x64100 | C10 | 1 | 1 | AUX CTL 0x64110 bit 19 |
| TC1 | 0x16F200 | C20 | 5 (PHY_F) | 3 | AUX CTL 0x16F210 bit 19 |
| TC2 | 0x16F400 | C20 | 6 (PHY_G) | 4 | AUX CTL 0x16F410 bit 19 |
| TC3 | 0x16F600 | C20 | 7 (PHY_H) | 5 | AUX CTL 0x16F610 bit 19 |
| TC4 | 0x16F800 | C20 | 8 (PHY_I) | 6 | AUX CTL 0x16F810 bit 19 |

Port register offsets are per-port absolutes, not a uniform
stride (e.g. the message-bus timer sits at +0xD8 on DDI A/B but
+0x58 on the TC ports). `TRANS_CLK_SEL` takes `intel_port_to_phy`
and `TRANS_DDI_FUNC_CTL` takes i915 `enum port` (PORT_TC1 = 3).
`DDI_CLK_VALFREQ(port)` and `DDI_BUF_CTL(port)` (DDI_CTL_DE) are
`_MMIO_PORT` registers for every port (TC1 = 0x64330 / 0x64300).
Type-C ports also use TCSS_DDI_STATUS (0x161500 + 4·tc), the
modular FIA `PORT_TX_DFLEXPA1` (FIA1 0x163880 for TC1/2, FIA2
0x16E880 for TC3/4), `XELPDP_PORT_HOTPLUG_CTL` (0x16F270 + 0x200·tc)
and the PICA interrupt block at 0x16FE50.

### 10.2 PHY programming (C10 / C20)

The port PLLs live inside the PHYs and are programmed over a
per-lane message bus (`M2P_MSGBUS_CTL` / `P2M_MSGBUS_STATUS`):
write transactions are committed or uncommitted, every
transaction is followed by a bus reset, and an ACK whose
command type doesn't match the transaction — or any answer
with the error bit set — fails the modeset with
`ModesetError::PhyBusFailure` rather than programming through
a wrong-generation PHY. C10 state is a 20-byte PLL table plus
CMN/TX bytes; C20 state lives in SRAM contexts (the program
writes the context the serdes toggle bit does not select,
then flips the bit). TX signal levels are VDR override
registers (SNPS preset tables), staged before training and
re-applied with the trained levels after. PLL enable order:
port clock control (MAXPCLK select, SSC PLLB for the MPLLB
tables; the external DP route enables SSC only when the VBT
allows it and the sink advertises 0.5% downspread, and then
also zeroes the C10 SSC bytes otherwise) → lane reset + powerdown staging (P2 reset, then P0
active) → PLL state → per-TX single-TX disables →
`DDI_CLK_VALFREQ` (C10 only) → PCLK PLL request/ACK. Every MTL
port also traverses the die-to-die (D2D) link, enabled
unconditionally in the retrain preamble.

### 10.3 Power wells and CDCLK

Xe-LPD well topology (`PWR_WELL_CTL2` = 0x45404, HSW
request/state encoding): PW_1 (idx 0, transcoder A + DDI A/B) →
PW_2 (idx 1, TC1–4 DDI lanes, owned external TC routes only) →
PW_A (idx 5, pipe A) → the port's AUX well, which on display 14 is
the channel's `XELPDP_DP_AUX_CH_CTL` power request (bit 19) with a
fixed 600 µs settle (`xelpdp_aux_power_well_enable`), never the ICL
`PWR_WELL_CTL_AUX2` request. CDCLK runs on the fixed 38.4 MHz MTL
reference: six rungs (172.8–652.8 MHz), the two lowest reached
by squash waveforms programmed in `CDCLK_SQUASH_CTL`. A qualified
display14.00 modeset with every pipe off programs the CDCLK its
resource transaction computes, raising or lowering it (§20,
"Display14 resource transactions"); the inherited path raises CDCLK
to the `pixel_clock ≤ 2 × CDCLK` floor and never lowers a faster
firmware setting. On Gen12 (Tiger / Alder / Raptor Lake, display
12/13) the inherited path programs the TGL model instead
(`intel_gpu_gen12_cdclk`, MIT Linux `display/intel_cdclk.c`,
`tgl_cdclk_funcs`): the `icl_cdclk_table` rung for the DSSM
reference strap (19.2 / 24.0 / 38.4 MHz) at or above the floor,
the DE PLL ratio in `BXT_DE_PLL_ENABLE` (0x46070) and the CD2X
divider in `CDCLK_CTL` (0x46000: divider select + pipe none +
decimal — never the SKL-only freq-sel bits 27:26 or SSA
precharge), with pcode frequency-request notifies
(`HSW_PCODE_DE_WRITE_FREQ_REQ` 0x17: pre DATA0 0x80000000, post
DATA0 = the `tgl_calc_voltage_level` level) around the change.
TGL has no CDCLK crawl or squash, so a VCO change is a full PLL
disable/enable and a same-VCO change rewrites only the divider;
the readback decodes ratio + divider and must match the rung
exactly. A refused pre-notify leaves the firmware clock and
degrades (the modeset proceeds), matching the standing
pcode-degrade contract. The display-14 current-CDCLK
readback decodes ratio + divider + squash popcount — under
squash the CDCLK_CTL decimal field is nominal and is not
trusted.

On Gen11 (Ice Lake / Elkhart Lake / Jasper Lake, display 11)
the same inherited path programs the ICL model
(`intel_gpu_gen11_cdclk`, MIT Linux `display/intel_cdclk.c`,
`icl_cdclk_funcs`): the `icl_cdclk_table` rung for the DSSM
reference strap (19.2 / 24.0 / 38.4 MHz) at or above the floor,
the DE PLL ratio in `BXT_DE_PLL_ENABLE` (0x46070) and the CD2X
divider in `CDCLK_CTL` (0x46000), with SKL pcode CDCLK-control
notifies (`SKL_PCODE_CDCLK_CONTROL` 0x7: pre DATA0
`SKL_CDCLK_PREPARE_FOR_CHANGE` 0x3 expecting
`SKL_CDCLK_READY_FOR_CHANGE` 0x1, post DATA0 = the
`icl_calc_voltage_level` level — three levels on ICL,
maxima 312 / 556.8 / 652.8 MHz; four on EHL/JSL, maxima
180 / 312 / 326.4 / 652.8 MHz) around the change. ICL has no
CDCLK crawl or squash, so a VCO change is a full PLL
disable/enable and a same-VCO change rewrites only the
divider; the readback decodes ratio + divider and must match
the rung exactly. A refused pre-notify leaves the firmware
clock and degrades, matching the standing pcode-degrade
contract. The port PLLs are the ICL combo PLLs
(`intel_gpu_gen11_dpll`, MIT Linux `display/intel_dpll_mgr.c`,
`icl_pll_mgr`): `ICL_DPLL_CFGCR0/1` at 0x164000/0x164004
(DPLL0), 0x164080/0x164084 (DPLL1), 0x164200/0x164204 (EHL
DPLL4), enable at 0x46010/0x46014 (DPLL4: `MG_PLL_ENABLE(0)`
0x46030); enable is power-enable, wait POWER_STATE, write
state, set ENABLE, wait LOCK (1 ms each). DP rates come from
the fixed combo tables and HDMI from the WRPLL search already
in `intel_gpu_pll` (`combo_coeffs`, `hdmi_wrpll_coeffs`).
`DPLL_CTRL1` (0x6C058) is a SKL/Gen9-only register — it is
transcribed in `intel_gpu_gen11_dpll` as a DISPLAY_VER 9-only
section and is never programmed on ICL. Watermarks are the
SKL method (`intel_gpu_gen11_wm`, MIT Linux
`display/skl_watermark.c`): 8 levels (no SAGV watermark on
Gen11), WaWmMemoryReadLatency +2 µs, the 16 Gb-DIMM +1 µs
workaround, transition wm0 + 14, DBUF 2048 blocks over slices
S1|S2 (`DBUF_CTL` 0x45008 / 0x44FE8), single-pipe allocation
of the whole DBUF to Pipe A's primary plane. DDI signal
levels are the ICL/EHL/JSL translation tables
(`intel_gpu_gen11_ddi`, MIT Linux
`display/intel_ddi_buf_trans.c` `.icl` entries) with the
ICL/EHL/JSL selectors (eDP 540 MHz and 270 MHz thresholds,
VBT low-vswing); programming the selected entries into the
PHY is Lane 5 modeset wiring. GMBUS on Gen11 uses the ICP
pin table (`GmbusPinTable::for_generation(Generation::IceLake)
→ Icp`, already landed with Lane 1).

### 10.4 Gates and named remainders

- `display_supported()`: Gen12, Gen11, Gen9, Gen9 LP and Meteor Lake.
  **Lunar, Panther and Wildcat Lake and Nova Lake-S stay off at this
  generation-level gate** — their display IPs require independently
  qualified clock-select fields, PLL tables and DDI arrangements; the MTL
  sequence must not claim them by generation. Each is reached only through
  its per-device route (10.5, §5).
- `backlight_supported()`: the Gen12, Gen11, Gen9 and Gen9 LP PWM
  blocks. MTL's panel backlight is the full-AUX DPCD owner
  (`intel_dpcd_bl::install_mtl`, §20 "Full-AUX panel backlight").
- Region enumeration: `RegionGeneration::XeLpg` — display at
  0x40000/0x40000 plus the TC block at 0x16F000/0x1000, and
  **no DPLL region** (Xe-LPG has no DPLL block; Gen12's DPLL
  range is the TC block here).
- External DP SST on DDI B and TC1–TC4 (Type-C ownership, owned
  PICA/south hotplug) is owned by `intel_gpu_xelpg_external` (§20,
  "MTL external outputs"); the inherited internal path still
  refuses direct TC routes. External DP and HDMI run on Pipes B–D next
  to the lit panel through the Pipe B–D owner (§20, "External outputs
  on Pipes B–D"); the panel's Pipe A is adopted, never driven by them.
  Which ports exist, which are legacy
  Type-C, their HDMI DDC pins and the SSC preference come from the
  board VBT (`intel_gpu_vbt`, §20 "VBT parser") when the OpRegion
  carries one.
- Lunar Lake reuses that service for source-qualified TC1–TC4 USB-C
  DP, combo C10 DDI B DP and HDMI on DDI B and declared legacy Type-C
  ports. It uses PICA power, display-20 TCSS pin assignment, D2D in
  `DDI_BUF_CTL`, and display-20 live resource transactions. UHBR remains
  refused.
- An opted-in, GMD-qualified Panther Lake display-30 owner reuses the same
  TC1–TC4 route, combo C20 DDI B DP, HDMI and the display-30 PICA/Cx0
  view. Its live transaction uses
  Xe3 PM demand and guardband-aware watermarks; every external transcoder
  programs and runs the mandatory fixed-refresh VRR timing generator between
  the DDI-function and transcoder enables. The exact WCL 30.02 model uses the
  same Pipe-A/display-30 core and a distinct TC1/TC2, Pipes B/C C20 profile.
  Its production entry requires `narf.intel.wcl_display=1`; on WCL combo
  DDI B, HDMI and a headless/unqualified function remain refused.
- Pipe A's DMC is reported dark after this lane's crtc disable and lit
  before its port PLL (`intel_dmc_disable_pipe` / `intel_dmc_enable_pipe`
  call sites); a successful owned modeset records its panel mode
  (`owned_panel_mode`) for the Pipe B–D owner's adoption.
- Not programmed by this lane: watermark / DBUF allocation and PM demand
  outside qualified display-14/20/30 all-pipes-off or live-panel layouts
  (those cases run the matching resource transaction of §20; other cases
  retain firmware's allocation, and an inherited layout cannot be
  adopted by the external route), the owned panel's PM demand at its
  trained eDP rate (it keeps the HBR3 reservation the KMS fixed profile
  checks), native HDMI 2.1 FRL (TMDS above 340 MHz with
  scrambling/SCDC and the computed SNPS C10 / C20 HDMI PLL states are
  owned by `intel_gpu_xelpg_hdmi`, §20), DP 2.0
  UHBR rates (the DP stack tops out at HBR3), a second external
  route at once (one `MtlExternalService` route; MST streams aside), and
  CDCLK notifications on the display-14 inherited path (display 14
  has no PCODE CDCLK mailbox; only the owned transaction sends
  PM demand — the Gen12 inherited path does send them, via
  `intel_gpu_gen12_cdclk`). Display-14 MST, TBT-alt tunnels and
  pin-assignment D are §20 "USB-C display transports"; panel training
  follows each sink level request through `TrainingAux`, as the Gen12
  combo path does.
- DSC is owned by `intel_gpu_xelpg_dsc` (§20, "Display-14 DSC"): the
  Pipe A eDP panel compresses when Linux would, and external DP routes
  compress with FEC. The same module picks the pipe bpp (§20, "Display-14
  6 bpc pipes"): the panel and external DP run at 6 bpc when the EDID or
  the VBT limit them to it or only 18 bpp fits, and an eDP panel that
  publishes `DP_SUPPORTED_LINK_RATES` trains with `DP_LINK_RATE_SET`.
  Bigjoiner, the uncompressed joiner, more than four slices and UHBR
  stay refused. The pipe scaler for panel fitting
  (`intel_gpu_xelpg_scaler`) is plumbed through
  `XeLpgModeset::with_panel_fit`; no production caller requests a fit.

### 10.5 Xe2_LPD — Lunar Lake display 20 (`intel_gpu_xe2lpd`)

Lunar Lake's display is version 20.00 (`xe2_lpd_display`: the display-14
`XE_LPDP_FEATURES` plus FBC on all four pipes and DBUF overlap detection).
`INTEL_LNL_IDS` binds 6420/64a0/64b0 to `lnl_desc`, which names no display:
the IP is known only from `GMD_ID_DISPLAY`. `DisplayIdentity` decodes the
complete current Linux map (14.00, 14.01, 20.00, 30.00, 30.02 and 35.00)
for read-only proofs and pins each identity's DMC container/payload ceiling
and maximum CDCLK plus pipe/FBC/DBUF topology. In particular, WCL selects
`xe3lpd_3002_dmc.bin`/480 MHz, has only pipes/FBC A-C and uses a 22 GB/s
programmed-bandwidth limit; NVL-S selects
`xe3p_lpd_dmc.bin`/787.2 MHz and the four-pipe/FBC `xe2_lpd_display` topology.
The headless post-FLR proof uses those masks, so WCL does not sample a
nonexistent Pipe D while NVL-S still refuses live Pipe-D state.
`DisplayIp::{Xelpdp,Xe2Lpd,Xe3Lpd,WildcatLake,NovaLakeS}` grants programming
authority only through its qualified route: 14.00 and 20.00 normally, plus
30.00/30.02/35.00 through the display-30 decoder. `display_route` binds 30.00
to exact Panther Lake with `narf.intel.ptl_display=1`, and 30.02 to exact
Wildcat Lake with `narf.intel.wcl_display=1`; 35.00 takes Nova Lake-S's own
route (§5). Crossed identities refuse before any write. The
production probe selects each exact identity only under its own option, and
the WCL hotplug actor retains 30.02 rather than rebuilding broad Panther Lake.
An absent display (GMD zero) and 14.01 (BMG, driven as
`DiscreteDisplayIp::Xe2Hpd`) remain typed refusals here. Display 20/30 runs the display-14 code with version dispatch,
not a copy of it.

Admission and the headless profile. Lunar Lake's existing profile is the
headless main GT, which owns the function through a driver FLR
(`__xe_driver_flr`). That reset includes display and would tear down the
panel a display takeover adopts, so the display route never runs it. Probe
takes the display route only with `narf.intel.lnl_display=1`, a display
20.00, Pipe A not fused off (`SKL_DFSM`) and Pipe A lit by firmware. The
decision is read-only, and nothing is read without the option. Every other
Lunar Lake function keeps the headless profile unchanged. That profile
still refuses while a boot framebuffer or KMS display exists, so the two
owners are exclusive per function.

On an admitted function, probe sequences the eDP panel and runs the
display-20 owned modeset on the firmware's Pipe-A surface (EDID mode). The
generation-level dispatch (`modeset_display`, relight) keeps refusing Lunar
Lake; everything below is reached only through the route.

Display-preserving GT owner. After a successful modeset probe installs the
function's GT owner with the `DisplayPreserving` profile
(`intel_gpu_gt_runtime::install_lnl_display`; `lnl_profile` selects it only
for Lunar Lake with the route and a lit mode, and keeps `Headless` for every
other LNL/PTL function). Linux xe never runs `__xe_driver_flr` at probe: it
arms it for `xe_driver_flr_fini`, `xe_device_shutdown` and wedging only.
Probe freshens the GT through `xe_uc_sanitize_reset` → `xe_guc_reset`
(`GDRST` = `GRDOM_GUC`), and `xe_gt.c::do_gt_reset` (`GRDOM_FULL`) is the
reset `gt_reset_worker` and `xe_gt_shutdown` run while display keeps
scanning out. NARF's `HardwareInit` already runs `GRDOM_GUC` then
`GRDOM_FULL` on the primary GT, and `MediaQuiesce` the same pair on the
media GT, before its cache policy may publish a GGTT PTE. That GT-only reset
meets the headless FLR's inherited-GT rationale (GuC, engines, contexts);
Wa_14015076503 around `do_gt_reset` is media 13.00 only. What the FLR also
gave is proved by `lnl::Receipt::admit_display`, which replaces the driver
FLR on this profile and is read-only except for one W1C: no FLR in flight
(`GU_CNTL`), a stale `GU_DEBUG.DRIVERFLR_STATUS` acknowledged so that any
later FLR fails every PTE write's receipt check, display 20.00 with Pipe A
fused in and lit, and no inherited display DMA outside the route's primary
(Pipes B–D dark, other planes and every cursor off, every DSB idle, FBC A–D
off, no pipe-DMC flip queue armed, no pipe B–D DMC enabled). Stolen memory
is not wiped and the GT arena never maps DSM, so the boot framebuffer stays
valid; neither the headless boot-scanout exclusion nor its client gate
applies. A BIOS-set `DRIVERINT_FLR_DIS` does not refuse this profile.
System suspend is admitted (`display_suspend_admitted`): resume relights the
panel through the display-20 modeset (`relight_display_locked`). The panel's
mode keeps runtime autosuspend off.

KMS owner. Probe then moves the console onto an owned surface in the Pipe-A
console window (the MTL probe pattern, `lnl_console_handoff`). Its GGTT
entries carry the PAT index of the firmware's own lit surface PTE
(`xelpg_ggtt_pte_flags` bits 52/53, used on Xe2), which must be 0. Once the
GT owner programs `xe2_pat_table`, PAT0 is Linux's (L4 uncached,
non-coherent), which display fetches treat as the firmware's. Any other index or a failed allocation keeps the firmware surface
and installs no KMS owner. `intel_gpu_kms::install` admits Lunar Lake only
after reading `GMD_ID_DISPLAY` 20.00. GEM flips then map with
`intel_gpu_scanout_io::display_pte`: `PteFormat::Xe2` and xe_pat.c's display
`idx[XE_CACHE_NONE]` = 3 (`XE2_PAT(0, 0, 0, 3, 3, 0)`, the index
xe_fb_pin.c encodes), admitted only while the GT owner's PAT3 reads back
0x3c. Display-20 deltas the owner uses: the DE pipe status it owns drops
both PIPEDMC faults and keeps the plane ATS fault
(`gen8_de_pipe_fault_mask`, display >= 20); the fetcher inventory covers FBC
A–D and five universal planes per pipe; and every KMS register read is
preceded by Wa_15015404425's four dummy writes
(xe_mmio.c::mmio_flush_pending_writes, `PLATFORM(LUNARLAKE)`). Fixed-mode
flips, console restoration and GT-reset recovery run through the display-14
owner unchanged. `PLANE_AUX_DIST` is absent on display 20 (`HAS_AUX_DIST`);
the presenter's read of it as zero is unchanged.

Cursor, color and DSB on display 20. At the pinned revision
`intel_cursor.c`, `intel_dsb.c` and `intel_color.c` have no branch between
displays 14 and 20: `MCURSOR_ARB_SLOTS` is display 13 only, `CUR_FBC_CTL`
ends at 13 and `HAS_HW_SAGV_WM` covers both; the DSB's
`DSB_ATS_FAULT_INT_*` start at 14 and `DSB_GOSUB_INT_*` at 30, and
`mtl_read_wm_latency` serves >= 14; `tgl_color_funcs` serves every
display >= 12, with 10-bit gamma and 131 degamma entries from 13,
`mtl_degamma_lut` from 14 and the next branch at 30
(`HAS_DOUBLE_BUFFERED_LUT`). `xe2_lpd_display` keeps `XE_LPDP_FEATURES`'
LUT sizes. So the KMS owner admits the display-14 cursor, CTM, gamma and
degamma LUTs and DSB transactions on display 20 (`card.intel_ctm`); the
cursor still proves the display-20 resource layout first. The cursor and
DSB owners take their page format from `display_pte` (`new_for`,
`reserve_for`): Xe2 PTEs at PAT3, admitted only while
`display_pat_programmed` reads 0x3c in `PAT_INDEX(3)`. PAT3 is the index
xe_fb_pin.c maps a cursor framebuffer with. xe maps its own DSB buffer
(xe_dsb_buffer.c, `XE_BO_FLAG_SCANOUT | XE_BO_FLAG_GGTT`) through the BO's
GGTT node at `idx[XE_CACHE_WB]` (xe_ggtt.c::__xe_ggtt_insert_bo_at); the
owner's command pages are CPU-WC and fenced before their PTEs are written,
so the uncached display index reads the same bytes and both owners keep the
one PAT entry their admission proves. The cursor's fault mask is the
display >= 20 `gen8_de_pipe_fault_mask` (plane ATS kept, both PIPEDMC
faults dropped).

Tiled primaries. A display-20 X or Tile4 primary is always fetched through a
display page table: `intel_dpt_configure` sets the `PLANE_CHICKEN` no-DPT
bit on display 14 only, and `intel_fb_uses_dpt` holds for every non-linear
modifier. The presenter builds it (`DptLayout`, `prepare_dpt`) the way
display >= 14 remaps a DPT framebuffer to a power-of-two stride
(`intel_fb_needs_pot_stride_remap`, `plane_view_dst_stride_tiles`): tile
row `r` starts at entry `r * dst`, `dst = roundup_pow_of_two(max(width
tiles, 8))`, each visible tile's entry is the framebuffer page's GGTT PTE at
PAT3 (xe_fb_pin.c::write_dpt_remapped, `idx[XE_CACHE_NONE]`) and padding
entries stay zero. Only a source stride no wider than `dst` is owned, so
`PLANE_STRIDE` is the source stride (`plane_view_scanout_stride`) and the
table equals Linux's for any framebuffer width up to the pitch. The table
is a WC system object (xe's `__xe_pin_fb_vma_dpt` system fallback) mapped
at PAT3 at a 2 MiB-aligned GGTT address (`tgl_plane_min_alignment`, 512 x
4 KiB), and `PLANE_SURF` names it; a panned tiled primary starts the table
at the view's tile origin (`DptLayout::with_origin`). Tile4 and X are advertised on display 20 through the display-14
qualification without the chicken read (`tiled_profile` returns the proved
IP, `Primary::capture_ip`), and their watermarks are the display-14 tiled
images (skl_watermark.c has no DPT term). Compressed modifiers
(`I915_FORMAT_MOD_4_TILED_LNL_CCS`) are not accepted: only plain X and
Tile4 reach the presenter and its PLANE_CTL never sets decompression.

Xe `SCANOUT` at creation. `DRM_XE_GEM_CREATE_FLAG_SCANOUT` is admitted on
the display-preserving profile (`UserBackend::display_preserving`) as
xe_bo.c::xe_gem_create_ioctl takes it: a WC system object marked for
scanout, EINVAL with WB caching. Headless LNL and PTL keep refusing it.
`NO_COMPRESSION` is admitted on every graphics 20+ part, which also
advertises `HAS_NO_COMPRESSION_HINT`, and is EOPNOTSUPP below, as in Linux;
the hint always holds, since the bind layer never admits a compressed PAT.

DC service. KMS install creates the DC service for display 20
(`intel_gpu_dc_states::service_profile`) under `DmcPlatform::Xe2Lpd`: after
each GT publication it acquires `i915/xe2lpd_dmc.bin`, loads and verifies it
under the display-20 rules (0x8000 ceiling, no Wa_16015201720,
`DMC_FQ_W2_PTS_CFG_SEL` after the load, the flip-queue reset and
`PIPEDMC_INTERRUPT` programming around each pipe-DMC enable/disable),
enables Pipe A's DMC and enters DC6 17 ms after the last DC_off release, with
Wa_15015404425 on its register view. `get_allowed_dc_mask` caps display 20
at `max_dc` 2, so DC6 is the target and DC3CO is never allowed.

PSR1 runs on display 20 and 30 with the display >= 20 branches of
intel_psr.c: `hsw_activate_psr1` (no `EDP_PSR_MAX_SLEEP_TIME`,
`LNL_EDP_PSR_ENTRY_SETUP_FRAMES`), `intel_psr_entry_setup_frames` (a setup
time longer than vblank takes one entry setup frame instead of refusing,
and Wa_18037818876 then refuses PSR1 without selective update),
`_intel_psr_min_set_context_latency` (the modeset programs
`TRANS_SET_CONTEXT_LATENCY` >= 1 for SRD_STATUS) and Wa_16025596647 (with
DC5/DC6 blocked by non-PSR pipes the DMC starts package-C exit at the
undelayed vblank, plus `intel_psr_set_non_psr_pipes`).

Display-20 deltas, each with its pinned source branch:

| Area | Display 20 against display 14 | Source |
| ---- | ----------------------------- | ------ |
| Power wells | Same PW_1/PW_A and per-channel AUX requests for DDI A; adds the `PICA_TC` well (`XE2LPD_PICA_PW_CTL` 0x16fe04, Type-C only, modeled) and a wider DC_off domain set | `intel_display_power_map.c::xe2lpd_power_wells`, `intel_display_power_well.c::xe2lpd_pica_power_well_*` |
| CDCLK | `xe2lpd_cdclk_table` (21 rungs, 153.6–652.8 MHz, squash on every rung); `CDCLK_CTL` carries `MDCLK_SOURCE_SEL_CDCLK_PLL` instead of the decimal field; same crawl/squash midpoint and wa_15010685871 | `intel_cdclk.c::bxt_cdclk_ctl`, `intel_init_cdclk_hooks`, `pll_enable_wa_needed` |
| MDCLK, DBUF and MBUS | Ratio `DIV_ROUND_UP(vco, cdclk)` into `MBUS_TRANSLATION_THROTTLE_MIN` and each slice's minimum tracker (doubled when joined), before lowering and after raising the clock; tracker state service not written; no 14.00 DBOX BW credits | `bxt_set_cdclk`, `skl_watermark.c::intel_dbuf_mdclk_cdclk_ratio_update`, `pipe_mbus_dbox_ctl` |
| Package C | `LNL_PKG_C_LATENCY` = level-1+ maximum latency rounded up to the pipeline time | `skl_watermark.c::intel_program_dpkgc_latency` |
| PM demand | Same pre-Xe3 fields; completion polled (Wa_14024400148), as the display-14 owner already does | `intel_pmdemand.c::intel_pmdemand_wait` |
| PHY | DDI A/B are C10 as on MTL (shared PLL tables) | `intel_cx0_phy.c::intel_encoder_is_c10phy` |
| DDI | D2D link enable/state in `DDI_BUF_CTL` bits 29/28 | `intel_ddi.c::mtl_ddi_enable_d2d` |
| Transcoder | `CHICKEN_TRANS` clears `DP_DSC_INSERT_SF_AT_EOL_WA` only (no FEC jitter WA) | `intel_display.c::intel_enable_transcoder` |
| Planes | No `PLANE_CHICKEN` no-DPT bit, so X/Tile4 primaries go through an owned power-of-two remapped DPT at a 2 MiB-aligned GGTT address; FBC on all four pipes | `intel_dpt_common.c::intel_dpt_configure`, `intel_fb.c::intel_fb_needs_pot_stride_remap`, `skl_universal_plane.c::{tgl_plane_min_alignment, skl_plane_has_fbc}` |
| Cursor, color, DSB | No register delta from display 14; Xe2 PTEs at PAT3 for the cursor and DSB pages; cursor faults without the PIPEDMC bits | `intel_cursor.c`, `intel_color.c`, `intel_dsb.c::dsb_error_int_*`, `intel_display_irq.c::gen8_de_pipe_fault_mask` |
| DSC | `XE2LPD_DE_CAP` may remove DSC; a stream that needs it is refused before any write | `intel_display_device.c::__intel_display_device_info_runtime_init` |
| DMC | `xe2lpd_dmc.bin`, 0x8000 ceiling, no Wa_16015201720, no pipe-MMIO restore, `DMC_FQ_W2_PTS_CFG_SEL` after load, flip-queue reset and `PIPEDMC_INTERRUPT` around pipe enable/disable; DC6 cap (no DC3CO) | `intel_dmc.c`, `intel_display_power.c::get_allowed_dc_mask` |

The shipped `xe2lpd_dmc.bin` (v2.29) loads main and pipes A–C inside the
display-14 program windows, so the display-14 window checks apply unchanged.

Refused or not wired on display 20: PSR2 and panel replay, compressed
primaries, XR30 and backlight PWM. PSR1, FBC on the HDR planes
(Wa_18038517565), tiled panning, system suspend and relight, TC1–TC4 USB-C
DP, combo DDI B DP, HDMI, PICA/TCSS ownership, external multi-pipe layouts
and the VBT port policy are wired. The route's probe-time
modeset window (`probe_window`: panel power sequencing, the takeover and the
PPS backlight gate) applies Wa_15015404425 like the KMS owner and the DC
service; only the read-only route decision ahead of it does not. Panther
Lake (display 30.00) uses the same TC1–TC4 route only when its opted-in KMS
owner has proved display 30.00. Wildcat Lake (30.02) uses the exact TC1/TC2,
Pipes B/C profile under its distinct option; both fixed-TG and resource deltas
are recorded in `intel_gpu_xe3lpd`.
## 18. Media engines — VCS / VECS (`intel_gpu_media`, #1022)

The Gen12 media engines brought to the §8 (RCS0) standard.
The execlists machinery of §8 is shared, not forked:
`intel_gpu_rcs` is generalised over an `EngineSpec` (register
base, descriptor engine class + instance, context-image
allocation bound, render-group presence), and each media
engine is an `RcsEngine` instantiated over its spec. Compiled
only under the gpu crate's `intel` feature; no new initcalls
(the engines attach lazily like RCS). Sources: TGL PRM
Vol. 2c (engine register blocks), cross-checked against
i915's `intel_gt_regs.h` (Gen11 media ring bases),
`intel_engine_cs.c` (engine table, per-class context sizes),
`intel_lrc.c` (descriptor upper-dword construction; the
Gen12 XCS register-state offset table), and `i915_reg.h`
(Gen11 media forcewake sub-domain registers).

Public interface:

- Engine table — `VCS0_SPEC` (base `0x1c0000`, video-decode
  class 1, instance 0), `VCS1_SPEC` (base `0x1c4000`, class
  1, instance 1), `VECS0_SPEC` (base `0x1c8000`,
  video-enhance class 2, instance 0);
  `GEN12_MEDIA_ENGINES` and `media_engines_for(gen)` are the
  inventory. The probe path announces exactly this set for a
  probed Gen12 part; userspace discovers engines through the
  Xe and i915 queries (§19). Gen11 (Lane 6) serves
  `GEN11_MEDIA_ENGINES` — VCS0/VCS2/VECS0, VCS2 at
  `0x1d0000` (`GEN11_BSD3_RING_BASE`) taking forcewake
  `VdBox(2)` — never the Gen12 set, which would announce a
  VCS1 the part does not have.
- Descriptor — `context_descriptor_for(spec, lrca, sw_id)`
  in `intel_gpu_rcs`: SW id at bits 37:47, engine instance
  at bits 48:53, engine class at bits 61:63 with the
  Gen12-era i915 class numbering (render 0, video decode 1,
  video enhance 2, copy 3, other 4). The RCS descriptor is
  the class-0/instance-0 special case and is byte-identical
  to its pre-generalisation form.
- Register state — `build_reg_state_for(spec, …)`: the
  shared PRM ENGINE CONTEXT layout at the engine's own base.
  The one structural delta from RCS: group 2
  (`R_PWR_CLK_STATE`) is render-only (i915's Gen12 XCS
  offset table has no third group), so media templates
  leave those dwords zero. Media image allocation bound is
  4 pages over the 2-page non-render hardware image
  (`GEN8_LR_CONTEXT_OTHER_SIZE`).
- VA batches — `RcsEngine::submit_ppgtt` (§8's engine, any
  spec): the batch-start carries the PPGTT address-space
  indicator, the batch is addressed at the VA equal to its
  GGTT offset (identity placement over the GGTT arena), and
  submission refuses with `PpgttNotAttached` when the
  context carries no root from §9's `attach_ppgtt`. This is
  the VA-batch step §8/§9 deferred to this lane.
- Forcewake — `MediaForcewake`: refcounted holds over the
  Gen11 media sub-domains (`VdBox(n)` request `0xa540 + 4n`,
  ack `0x0d50 + 4n`; `VeBox(n)` request `0xa560 + 4n`, ack
  `0x0d70 + 4n`), masked-write protocol with the
  aggregate-domain discipline (poll-counted ack budget,
  one clear→set re-kick, rollback on timeout). Production
  submissions and engine bring-up run inside the engine's
  sub-domain hold; completion polling takes none (the CSB
  is host memory). Composition with the aggregate MEDIA
  domain of #1013 is at the marked seam in
  `submit_media_dwords` — the sub-domain hold nests inside
  it once that lane lands.
- Production glue — `submit_media_dwords(engine, dwords)` /
  `poll_media_completions(engine)` over `MediaEngineId`,
  mirroring §8's glue. Every production engine on the
  controller allocates from the one arena
  (`intel_gpu_rcs::production_arena`), so objects never
  alias across engines.

Invariants:

- One engine's contexts, rings, status page and doorbell
  never alias another's: the fixtures run all three engines
  concurrently over one arena and one register file and
  assert per-engine descriptors, completions and
  breadcrumbs; a wedged engine (hardware never posts CSB)
  does not block a peer's submissions or completions.
- A failed forcewake acquire holds nothing; a media
  submission's doorbell is always inside a held sub-domain
  (fixture-pinned write order).
- The generalised §8 paths are regression-pinned: the RCS
  descriptor and RCS register-state template are asserted
  byte-identical to their pre-generalisation forms, and the
  existing §8 fixtures pass unchanged.

Flagged for first-silicon verification: the per-SKU media
engine set (a part with an engine fused off is still listed
— the media fuse readout that trims the table is not
modelled); the 4-page media image bound; and the descriptor
class numbering's era (later i915 trees renumbered their
internal class enum — the Gen12 execlists construction
governs here). BCS0 (copy, base `0x22000`) runs on the GuC
owners and on the Gen9/Gen11 execlists owner
(`intel_gpu_legacy_owner`); MTL media runs on its own media
GT (§20).


## 19. Render UAPI and 3D admission (in progress)

Production GuC owners identify as native Xe on both render and primary opens.
Exact Xe command encodings take precedence over the explicit supported i915
compatibility subset; unknown encodings never select an ABI by number alone.
The native path implements engine/memory/config/GT/HWCONFIG/topology queries,
correlated per-engine/CPU timestamps through the live reset/forcewake owner,
system/visible-DG2/BMG GEM creation/mmap, persistent VM binding metadata, published
render/copy/compute placement queues and software bind queues, binary/timeline
syncs, GPU and CPU user fences and masked waits.
Its immutable per-execution PPGTT roots retain partial BO ranges and aliases;
scratch/NULL mappings use shared hardware NULL tables with private path copies.
Xe GPU ordering is explicit while terminal dma_resv fences exclude CPU copies.
VM-attached BO identities cannot be exported or rebound to a different VM.
Native queue priorities and timeslices reach the real GuC policy KLVs.
Legacy backends retain the i915 compatibility profile described below.
Remaining completion work is tracked in §20. Mesa and
physical execution remain separate acceptance gates.

The public contract is `spec.md` §3, "Intel render UAPI and address-space
admission". The modules are `intel_gpu_uapi` (wire definitions),
`intel_gpu_gem` (owned system memory), `intel_gpu_render` (per-open dispatcher,
contexts, VM handles and queries) and `intel_gpu_exec` (softpin admission and
immutable PPGTT residency). Same-card PRIME shares owned objects and stable,
globally distinct mmap offsets; explicit sync-file imports join the same
owned reservation. Another native Xe card imports through `intel_gpu_prime`
(below). Both primary and render nodes route these requests before shared
DRM/KMS dispatch and acquire mmap backing atomically.

Cross-device PRIME follows Linux `xe_dma_buf.c`. Export admits system and
VRAM objects (VM-private and USERPTR objects refuse). An importer's
attachment keeps peer-to-peer only where `narf_io::p2pdma`
(`pci_p2pdma_distance` over `narf_bus::p2pdma::LiveTopology`) finds a path
from the exporter's PCI function; otherwise the object must have a system
placement (`xe_bo_can_migrate(bo, XE_PL_TT)`), so a VRAM-only object
refuses with EOPNOTSUPP. Pinning (`xe_dma_buf_pin`) keeps VRAM only while
every attachment is peer-to-peer, else migrates the idle object through the
eviction copy. An object already pinned in VRAM, or a VRAM scanout object,
refuses a system pin with EINVAL. Mapping returns the exporter's system
pages, or for a peer the LMEM BAR bus addresses in segments of at most
2 GiB; VRAM that is not wholly CPU-visible refuses with EOPNOTSUPP. NARF
importers are static (no `xe_dma_buf_move_notify`): mapping pins for the
attachment's life, which excludes eviction, exec re-migration and the
suspend drain, so a pinned VRAM export refuses system suspend. The
exporter's runtime-PM reference is held from that pin. The import is a
system-placed object sharing the exporter's reservation, mapped at its
first native VM_BIND (XE_COH_NONE and compressed indices refuse). It has no
CPU copy, mmap, migration, i915 compatibility exec, ADDFB or cursor use. A
reimport returns its handle; a re-export names the original buffer. Live
imports request peer-to-peer only with `narf.intel.prime_p2p=1`. Native
fixtures (`drivers/gpu/intel_gpu_prime`, the smallbar suite and
`io/p2pdma`) cover BAR bus addresses, migration, the pinned, VRAM-only and
nonvisible refusals and import binding.

Native terminal fences now back the shared per-object dma-buf reservation.
GuC and Gen12 resident admission check synchronous conflicts across the
whole residency list before adding READ/WRITE fences. Readers can overlap;
unflagged conflicting work returns busy. Qualified BMG per-object
EXEC_OBJECT_ASYNC skips only that entry's prior implicit GPU waits; mixed
unflagged entries still require generation-checked final admission. Every
entry receives its terminal READ/WRITE fence, including ASYNC, and kernel CPU
copies use the same admission gate and observe all conflicting reservations. Cache publication follows
reservation. Failure after reservation releases the graph before signalling;
uncertain DMA lifetime keeps reservations through timeout/cancel until proven
full reset. Independent GuC LRCs do not share an ordered dma-fence context.
GEM_BUSY exposes render-class reader/writer bits. Async GEM_WAIT preserves one
relative timeout deadline across parking and writes remaining nanoseconds;
PREAD/PWRITE and CPU-domain waits respect reservations. PRIME SYNC START waits
for conflicting access, END orders coherent RAM, and shared names and
EXPORT_SYNC_FILE use the generic dma-buf fd/copyout protocol. External
IMPORT_SYNC_FILE batches serialize with CPU/native reservation admission;
foreign callbacks and final drops remain outside admission/reservation locks.
CPU/implicit job conflict decisions validate the observed addition generation
before copying or publishing, including racing imports. Xe GPU ordering stays
explicit. GETPARAM HAS_EXEC_ASYNC (43) reports 1 only for current nonzero BMG
admission with published engines, otherwise 0, without waking the GT. ASYNC is
bounded to ordinary system WB softpin objects and same-card WB imports; local,
WC, VM-owned and pinned-user objects and other platforms refuse. Explicit input
fences and same-context order remain required. CPU mmap stores remain ordered
by the client; reservations do not freeze or revoke an existing alias. Mesa execution
acceptance remains separate. Linux references are
`i915_gem_busy.c`, `i915_gem_wait.c`, `dma-resv.c` and `dma-buf.c` at the pinned
source revision below. Native smokes exercise alias/PRIME lifetime, independent
readers, all-or-nothing conflict admission, async deadlines/cancellation,
CPU-copy exclusion, sync-file copy faults and GuC terminal/reset boundaries.

Live MTL/Arrow, DG2 and BMG owners now accept async nonsecure softpin
EXECBUFFER2/WR on RCS0. Per-open contexts serialize submissions and preserve
their saved LRC state across fully retired jobs; independent contexts begin
from the golden template. The entry sets BB_START bit8 for nonsecure PPGTT,
with kernel rings/images/tables absent from user mappings and the RCS register
policy reverified before admission. Nested commands and mutable leaf BOs
remain untrusted; hardware privilege checking is required throughout execution.
The complete copied residency plan and context survive handle/fd close and
cancelled waiters. Admission/cache failures roll back claims; uncertain saves
retain ownership until proven full reset. Saved CPU images have a 64-MiB cap.
The backend publishes RCS0, relevant i915 capability bits, the real CSS
submission-interface version and i915 loader identity only after startup's
default-state and PPGTT probes pass. Loss/suspend closes readiness; proven stop
allows a fresh GT epoch, with old contexts refused/banned and no automatic
batch replay. Gen12 production execlists helpers
refuse Meteor/Arrow Lake before MMIO. The physical GuC owner now supplies
per-card startup, kernel context scheduling, completion and full-engine reset
ownership. Live geometry/compute DSS and EU fuses now feed per-card topology
queries. Explicit sync_file IN/OUT fences, binary syncobj arrays and timeline
extensions now connect to the exact terminal job fence. Each open owns its
own binary/timeline syncobj table; dependencies and signal objects survive
handle/fd close. Output fd reservation and rsvd2 copyout precede non-failing
enqueue, so EMFILE/EFAULT cannot queue an unreported job. Array/extension
bounds, flags, cycles and timeline WAIT|SIGNAL conflicts fail before publication.
FENCE_SUBMIT now accepts the same input sync_file fd as FENCE_IN, with those
two input flags mutually exclusive. Native Intel leaves satisfy SUBMIT after
the owner observes GuC's scheduling-enable ACK; foreign leaves require
completion. Syncobj/sync_file round trips retain the native leaf. FENCE_OUT
still exports terminal completion, and GEM reservations, same-context ordering
and syncobj WAIT retain terminal gates. Loss before enable ACK keeps SUBMIT
pending until proven full reset publishes a terminal error. Native Rust smokes
cover ACK timing before any GPU breadcrumb, ioctl admission before completion,
fd close/wire edits, mixed foreign/native timeline chains, binary/timeline WAIT,
invalid flag/fd combinations and reset ownership. Linux references are
`i915_gem_execbuffer.c::eb_fences_add`,
`i915_request.c::i915_request_await_execution` and `__await_execution` at the
pinned revision below. These model checks do not establish silicon/Mesa acceptance.

`intel_gpu_guc` now supplies validated CSS component ranges and coherent CTB
send/receive primitives. `intel_gpu_guc_firmware` acquires a bounded immutable
MTL/Arrow, DG2 or BMG GuC-70 image through invoked registry/blob capabilities,
preserving its identity. `intel_gpu_guc_transport` owns coherent GGTT CT memory and the
graphics-GuC MMIO registration/enable/disable state machine. Its partial
registration, timeout and broken-CT paths retain allocations until disable
acknowledgment or proven reset. `intel_gpu_gt` provides exact DG2/BMG PCI identity
and firmware profiles, separate from the integrated display table.

`intel_gpu_guc_boot` owns the GuC reset, WOPCM layout, minimal ADS/log allocation,
cache publication, firmware DMA and authentication state machine for these three
profiles. Minimal bootstrap disables scheduling and advertises no engines. The
physical owner holds forcewake/runtime-PM, serializes resets/DMA and programs
PAT/MOCS before exposing mappings. All allocations stay above the largest
admitted WOPCM window and below the GuC GGTT ceiling. A timeout or failed authentication retains every
potentially live allocation. The original no-HuC bootstrap release requires
verified GuC reset plus firmware DMA idle, or an explicit unsafe proof from the
GT owner. Exact-TGL exposed HuC additionally requires the enclosing full Gen12
engine-reset/media-ACK retirement; lower Staged/Stopped labels and GuC-only
reset are insufficient. Other profiles preserve their own mapping-retirement
and wake-release contracts. One-shot DMA publication
does not make shared CT cursor lines coherent: CT requires an allocator that
explicitly supplies coherent memory. Physical x86_64 system allocations gain
that proof after platform cache-policy installation; ARM host-bridge coherency
remains unproven.

`intel_gpu_guc_gt::GuCGt` joins the bootstrap, one CT transport and the GT
kernel forcewake request under one owner. The correct ACK is 0x130044 on DG2
and 0xdfc on MTL/Arrow/BMG (graphics IP 12.70+); a high value at the other
address cannot authorize GT access. Wake acquisition refuses another kernel
owner and preserves other requestors with masked writes. Ready/CT operations
validate request and ACK; wake loss closes admission. Shutdown recovers wake,
proves GuC reset and firmware DMA idle before retiring CT, then clears the
request and waits for sleep ACK. Cancelled waiters preserve the transaction;
unverified drop retains the whole allocator/MMIO object graph. The owner is
terminal after stop. A physical owner with a scheduler additionally proves full
graphics-engine reset before retiring RCS references.

`intel_gpu_gt_hw` adds capability-invoked MMIO, render-well wake and bounded
initial GuC/full-engine quiescence before PAT/MOCS programming. Staged physical
allocations reserve frames/VA without writing inherited GGTT entries. Installed
policies use MTL PAT3, DG2 PAT0 and BMG PAT2; BMG uses the Xe2 five-bit leaf
encoding and source five-level root. MTL also installs UC PAT2 for
non-leaf PPGTT reads and Linux's non-coherent WT PAT1 (Mesa's scanout and
write-combining index). DG2 installs the rest of Linux's Xe-LP table (PAT1
WC, PAT2 WT, PAT3 UC). MTL installs PAT0 (WB, non-coherent) as Linux does,
under the inherited display's PTEs. Xe2 and Xe3 install all of
`xe2_pat_table` / `xe3_lpg_pat_table` (Battlemage's first 28 entries,
Wa_16023588340), `PAT_ATS` and, on Battlemage, `PAT_PTA`.
MCR steering is serialized and restored, and BMG PTE writes drain the G-unit.

`intel_gpu_gt_runtime` starts a persistent per-function owner from Stage::Late,
validating D0, live PCI identity, PF registers and disabled SR-IOV VFs. Source
descriptors with `has_sriov` retain that PF-only proof in their GT window and
GGTT arena, so every later register or PTE operation revalidates it. An
integrated Gen12 or MTL/Arrow owner requires an owned scanout, a firmware
render handoff, a probe-time proof that Pipe A-D all have both
`PIPECONF_ENABLE` and `PIPECONF_STATE` clear, or one that every enabled plane
and cursor fetches below 192 MiB with no DSB running (`planes_below_arena`);
an unavailable register fails closed. The no-scanout
profile remains D0-only because stopped fetchers do not confer runtime-PM
authority. LNL/PTL retain their separate FLR-gated headless profiles beside
their display-preserving routes, and DG2/BMG apply the same below-arena rule to
an inherited display (`validate_discrete_display`). Each owner retains the registered card,
current PCI authority, dedicated arena and immutable firmware asset. Async
system-PM preparation proves stop before saving configuration; the synchronous
callback only verifies readiness.
Async resume restores D0/configuration and any owned display, then
rebuilds using a fresh arena/cache-policy proof. Failed cleanup retains uncertain
resources without an unbounded reset retry.

Scheduling requires CSS submission-interface major 1 (byte 68), separately from
the firmware release. After HWCONFIG, the owner stops GuC, updates ADS for RCS0,
reloads/authenticates with LiteRestore, and enables coherent CT. GuC
autonomous engine reset is enabled (`guc_policies.global_flags` 0, as Linux). The scheduler
owns HWS plus a distinct LRC and 8-KiB ring for each of at most 64 kernel probe
contexts. MTL/DG2 use 14-page LRCs, BMG four pages, with Xe register-state groups.
The original safe submission entry admits a fixed owned GGTT breadcrumb.
The resident interface below adds trusted kernel PPGTT work; the separate
nonsecure userspace entry requires the startup probes and live backend.

`intel_gpu_guc_sched` sends GGTT invalidation, context registration, policy,
enable, disable and deregistration through real CT rings. Full rings retry
without losing phase; stale/foreign events and deadlines close admission.
Context IDs are reused only after verified retirement, with independent
request stamps and TLB cookies. Fences require the GPU
breadcrumb, saved ring head, deregistration ACK and correlated final TLB
completion; scheduling ACKs alone cannot complete a job. A canceled waiter
leaves the context owned. Uncertain jobs survive until GuC reset/DMA idle plus
GRDOM_FULL; then fences report Reset and render/GT wake releases are acknowledged.
The service logs startup success only after its hardware probe retires. The
async `kernel_probe(card)` API queues another owned context on that function.

The same owner now accepts trusted kernel resident PPGTT batches through
unsafe `submit_kernel_batch`. `prepare_for_gt`
selects the installed WB leaf policy (MTL/Arrow PAT3, DG2 PAT0, BMG PAT2).
MTL/Arrow non-leaf entries and PDP0/PTBP use a separately installed UC PAT2;
DG2/BMG retain their WB policy for those entries. Every immutable table
and BO is cache-cleaned before context registration; Xe-LPG's non-coherent
table walker cannot observe dirty CPU cache lines. Registration sets PPGTT
mode and the kernel ring uses PPGTT batch start, preparser/TLB/cache
invalidation, MTL AuxCCS invalidation, DG2/Xe-LPG depth-flush workaround, render-cache
drain and a separate GGTT post-sync fence. The submitted tail, deregistration
and final invalidation must all agree before tables and BOs are released and
the terminal fence is published. Uncertain residency survives until full reset.

`submit_ppgtt_probe` / async `kernel_ppgtt_probe(card)` provide a safe fixed
kernel diagnostic with unexported code/result BOs at two separate 48-bit
addresses. After completion `PpgttProbeResult::verify` checks the stored value,
every guard byte and the unchanged code page. Startup runs this after the
original GGTT probe before reporting readiness. Native Rust models walk the
real production tables, check literal command/PAT vectors, execute the store
through translated physical pages and verify retirement/reset ownership.
The RCS default-context priming path now selects Linux's context workaround
and tuning tables using stable GMD ID and fuse observations: Xe-LPG
12.70/12.71/12.74 and Xe2 HPG 20.01/20.02 remain distinct. Non-masked registers
use GPU MI_MATH read/modify/write through a non-terminated MCR instance;
HWCONFIG physical maxima select the DSS layout, while observed L3 fuses select
the cache bank. Temporary GPRs and CS selective-read steering are reset after
use. Every admitted profile explicitly seeds all fifty SVG command headers
(Wa_14019789679); Xe2 substitutes pipelined DRAWING_RECTANGLE_FAST for the
non-pipelined DG2/Xe-LPG command. This corrects the earlier DG2-only selection.

`begin_context_defaults` owns an exclusive seed → complete retirement →
different-context execution/retirement → CPU synchronization → golden copy →
device synchronization transaction. The seed image stays owned through the
switch; submission is Busy while the priming fence is pending. Priming is
refused after any resident kernel batch has been accepted, so its state cannot
contaminate the template. The fixed GGTT diagnostic may precede priming. Only the
successfully published template makes `context_defaults_ready()` true. New
contexts copy opaque saved state, clear their status, enable restore and assign
their own ring/root/timestamp. The physical service primes between its GGTT
and PPGTT probes. Cancellation or missing save/synchronization proof retains
all uncertain backing until GuC plus full-engine reset; it cannot complete the
priming fence early.

Graphics-GT/RCS0 MMIO workarounds now run in `PreparingScheduling` before
ring publication and the scheduling GuC reload. Linux's GT/engine tables and
tunings select DG2 G10/G11/G12, Xe-LPG IP and stepping, and Battlemage
20.01/20.02. Battlemage compression tunings follow the observed flat-CCS
enable bit, and the EU-stall workaround follows gaps in live DSS groups.
Non-masked fields use host read/modify/write through live MCR targets; DG2
implicit SF/SQIDI steering is initialized independently. Masked registers
preserve unrelated fields. Modern steering semaphore contention yields with
a deadline, and selector/semaphore ownership is restored on every outcome.
Readable registers are preflighted before WA writes and verified afterward;
DG2 CACHE_MODE_SS follows Linux's no-readback exception. Failure closes
scheduling admission, retaining owned storage until full reset. Out-of-band
workarounds remain separate work.

RCS0 now also installs an explicit nonprivileged register policy before ring
publication. All twelve FORCE_TO_NONPRIV entries are cleared to RING_NOPID
and verified before the three Linux Xe OA grants are installed in address
order: status RD, head/tail/buffer/control RD, and MMIO trigger RW. Unused slots
stay at NOPID; inherited addresses, ranges and access bits cannot survive.
The source is `xe_reg_whitelist.c`, `regs/xe_engine_regs.h`, `regs/xe_oa_regs.h`
and i915's `intel_engine_apply_whitelist` at the pinned revision. The complete
policy is checked after firmware reload, CT enablement and before kernel
submission/default priming. Drift closes admission without a live repair and
keeps existing jobs/reservations until proven full reset. Native literal vectors
and hardware conversations cover all six admitted IP profiles, failed clears,
unavailable/cross-slot writes, reload/CT drift and reset ownership. This does not
enable an OA stream or legacy Gen12/media policies.

The firmware-side workaround path binds stable graphics IP/stepping before
GuC's first reset/DMA and refuses a different identity on scheduling reload.
GuC boot parameters now carry DG2 die and Xe-LPG stepping flags. Source-defined
zero-length KLV headers occupy a dedicated ADS page, with packed pointer/size
fields published before DMA cache synchronization. DG2/Xe-LPG use MGSR and
BB-stack-pointer records; Battlemage 20.01 adds PFQ polling and asynchronous
compute MTP records, while 20.02 keeps its narrower reset/BB-stack list.
Native wire fixtures check each variant and reject bad live identity before
DMA; reload checks preserve firmware records and retain uncertain ownership.

`intel_gpu_topology::GtTopology` reads main-GT geometry/compute DSS and EU fuses
after initial quiescence, with two matching samples and current wake checks
before firmware DMA. All three admitted profiles use one geometry and one
compute register; Xe2 BMG does not use Xe3's three-register DSS layout. MTL/DG2
expand paired SIMD8 EU bits; BMG preserves SIMD16 bits. The admitted EU format
is eight fuse bits; unexpected upper bits, empty units and unstable readings
refuse discovery. Full 32-bit DSS masks remain valid. Compute-only fuses can
describe a GT but cannot authorize the RCS0 kernel scheduler.

Each card publishes its immutable observed snapshot through a live GT owner,
separately from HWCONFIG maxima. Identical resume observations are idempotent;
changed fuses refuse restart. QUERY_TOPOLOGY reports the geometry/compute union
and QUERY_GEOMETRY_SUBSLICES the geometry subset in i915's single software-slice
wire layout, preserving sparse DSS indices and per-DSS EU masks. Missing
snapshots return -ENODEV; data queries check readable headers, short capacity
and user-copy failures with independent per-item errors. Snapshots remain
queryable on both DRM nodes after verified stop frees all GT DMA storage.
They do not admit userspace engines or commands.

Before CT enablement, `GuCGt::begin_hwconfig` performs the source-defined
GET_HWCONFIG size query and GGTT copy through the same bounded MMIO mailbox
protocol. The destination is zeroed, cache-cleaned and GuC-TLB-invalidated
before publication, then synchronized for CPU reads after the copy reply.
All-ones scratch reads are rejected as unavailable hardware. A validated
immutable `intel_gpu_hwconfig::HardwareConfig` preserves exact KLV bytes,
unknown keys and vector values; scalar lookups reject vectors and duplicate
keys/invalid extents fail acquisition. The DMA destination remains owned
until verified stop, including on timeout, cancellation or cache failure.
The snapshot is capability data, not an active engine/fuse inventory, and
does not open the userspace submission gate.

The DRM registry now recognizes `intel-gpu`, fixing private ioctl/mmap routing
on both primary and render nodes. Per-card `DeviceInfo` retains an immutable
snapshot from that card instance, with exact integrated/DG2/BMG profile lookup.
`IntelGpuCard::publish_gt_hwconfig` accepts one snapshot from an awake Ready,
CtReady or SchedulingReady GT with matching device ID. The PCI owner must supply
the GT belonging to that physical function, including with duplicate PCI IDs. Static CPU bytes
survive GT shutdown; DMA allocations stay with the GT and can all be reclaimed
after verified stop. Another card's slot remains absent. The integrated probe
retains its registered card Arc for the physical service. Eligible startup
publishes HWCONFIG before the scheduling reload; failed/ineligible discovery
continues to report it unavailable.

HWCONFIG queries follow local Linux `i915_query.c::query_hwconfig_blob`: exact
bytes/order, two-pass lengths, -ENODEV for absence, -EINVAL for a short buffer,
and per-item -EFAULT for a bad copy. GuC submission-version reports the live
backend's scheduling interface and -ENODEV without one. Native tests traverse both DRM
node types, GEM/mmap ownership, the GT discovery/publication chain and snapshot
queries after all GT DMA is freed.
RCS0 availability comes only from the live backend after execution-tested startup.

Gen12 owned resident submission, cache-flushed
post-sync breadcrumbs, terminal fences and loss retention have native hardware
models. Real Mesa acceptance remains outstanding.

The memory audit corrected previous x86-like GPU PTE assumptions. Gen12
PPGTT PAT bits are 3,4,7 and Xe-LPG adds bit62; Xe-LPG GGTT uses bits52,53.
Gen12 system GGTT has no PAT bits. Intermediate PPGTT entries include RW and
their independent two-bit PAT policy. The legacy Gen12 attachment keeps its
raw-root contract; GuC PDP0/PTBP uses a complete encoded descriptor.
No GPU NX/LRU permission is claimed.
The common physical range is conservatively bounded to 46 bits. PAT numeric
indices do not define cache policy: physical startup now programs the owned
GGTT and PPGTT policy before admitting kernel or user work.

Native Rust fixtures use literal ABI/PTE vectors, fault-contained user-memory
models, cross-open ownership failures, copy-failure rollback, extension cycles,
query sizing/item errors, hostile residency placement and actual production
PPGTT ownership after GEM/fd close. They do not establish silicon or Mesa
interoperability.

Primary references:

- [Linux DRM i915 uAPI](https://docs.kernel.org/gpu/driver-uapi.html#drm-i915-uapi),
  and the MIT `include/uapi/drm/i915_drm.h` wire definitions.
- [Intel GPU page-table fields](https://github.com/torvalds/linux/blob/v6.12/drivers/gpu/drm/i915/gt/intel_gtt.h),
  MIT; fixed encoding vectors also follow `gen8_ppgtt.c` and `intel_ggtt.c`.
- [Logical context root registers](https://github.com/torvalds/linux/blob/v6.12/drivers/gpu/drm/i915/gt/intel_lrc_reg.h), MIT.
- [GuC/HuC firmware layout](https://docs.kernel.org/gpu/xe/xe_firmware.html),
  background for the GuC firmware owner.
- [Gen12 render and XCS completion streams](https://github.com/torvalds/linux/blob/v6.12/drivers/gpu/drm/i915/gt/gen8_engine_cs.c),
  MIT command ordering and generation workarounds, with `gen8_engine_cs.h` and
  `intel_gpu_commands.h` bitfields.
- [GuC CT registration](https://github.com/torvalds/linux/blob/v6.12/drivers/gpu/drm/i915/gt/uc/intel_guc_ct.c),
  MIT; `intel_guc.c` and the actions/KLV/message ABI headers specify the MMIO
  mailbox, receive-first registration and CONTROL_CTB acknowledgment protocol.

GuC bootstrap and discrete identity were cross-checked against the local Linux
checkout at `b90c984d615e8ce2af96f5b1411a962d83fed2ad`: MIT-licensed
`include/drm/intel/pciids.h`, `drivers/gpu/drm/xe/{xe_uc_fw.c,xe_guc.c,xe_wopcm.c,
xe_guc_ads.c,xe_guc_fwif.h,xe_guc_tlb_inval.c,xe_ggtt.c,xe_force_wake.c,
xe_guc_hwconfig.c,xe_mocs.c,xe_pat.c,xe_gt_mcr.c,xe_bo.c,xe_lrc.c,
xe_hw_engine.c,xe_guc_submit.c,xe_gt_topology.c,xe_vm.c,xe_ring_ops.c,
xe_gt.c,xe_wa.c,xe_tuning.c,xe_irq.c,xe_userptr.c}`,
`drivers/gpu/drm/i915/gt/{uc/intel_guc_hwconfig.c,intel_sseu.c}`,
`drivers/gpu/drm/i915/i915_query.c`, `include/uapi/drm/i915_drm.h` and
`drivers/gpu/drm/xe/regs/{xe_guc_regs.h,xe_gt_regs.h,xe_irq_regs.h,xe_lrc_layout.h}`,
`drivers/gpu/drm/xe/instructions/{xe_mi_commands.h,xe_gpu_commands.h,
xe_alu_commands.h,xe_gfxpipe_commands.h}` and the
GuC actions/KLV/CSS ABI headers. Native Rust models pin register/ADS values,
reset/DMA/full-engine stop proofs, cache-policy publication, current authority,
two-context execution, 64-context pressure/CT backpressure, context retirement,
allocation rollback, coherence refusal and per-card query lifetime. These tests
do not establish firmware boot or context execution on Intel silicon.

### Copy engines (BCS0 and BMG BCS8)

BCS0 (MMIO 0x22000, GuC class 3, Xe COPY) is part of every admitted graphics
IP's Linux engine mask and is never fused: Linux `read_copy_fuses` applies only
to PVC and Xe3+. `intel_gpu_engine` owns the literal per-engine table. Its LRC
is two pages; the register image follows `gen12_xcs_offsets` on DG2 and
Xe-LPG (Linux selects it for COPY before Xe2, not `dg2_xcs_offsets`) and
`xe2_bcs_offsets` on BMG, whose third LRI saves BCS_SWCTRL/BLIT_CCTL. Ring
enable mirrors `xe_hw_engine_enable_ring` with RING_CMD_CCTL's uncached MOCS.
Default state is the source's BLIT_CCTL RMW only: no render 3D state and, on
these platforms, no LRC workaround. BCS0 shares RCS0's render forcewake
domain. BMG 20.01/20.02 also apply the ENGINE_BASE engine entries for BCS0.
The NONPRIV deny fill, ADS publication, priming order and Xe UAPI surface are
described in `spec.md`. The i915 compatibility profile reaches BCS0 through
the legacy BLT ring and proto-context engine maps.

BMG 20.01/20.02 also admits architecture-present BCS8 (MMIO 0x3ee000,
physical COPY8, logical COPY1). Its ADS physical COPY enable mask is 0x101;
logical COPY1 submits with mask two. Each instance has independent register
saves, default state, nonprivileged deny slots, IRQ ownership and a private
PPGTT startup store probe which must retire and validate before publication.
Native Xe queues and explicit i915 context maps can select COPY1. Linux
reserves the highest copy engine for USM; NARF currently has no USM owner.
Adding USM must reserve/revoke ordinary userspace availability.

### Compute engines (CCS0–3)

DG2 derives physical compute slices from live DSS quadrants; BMG uses
XEHP_FUSE4 CCS_EN. The integrated Xe-LPG profile remains one CCS.
`narf.intel.ccs_mode=N` (default one) selects N compute engines on DG2/BMG,
where N must divide and not exceed the live slice count. Only the first N
present physical CCS engines are owned, with dense user COMPUTE instances;
sparse physical CCS2/3 may therefore become logical COMPUTE0/1. The fixed
slice assignment follows Linux's round-robin partition over present slices.
Bad/ambiguous boot settings refuse startup; there is no live setter.

All selected engines have per-instance registers, saved/default state,
nonprivileged policy, ADS entries, IRQs, timestamp/watchdog attribution and
private PPGTT startup execution proofs. The raw fuse mask, selected physical
set and partition remain invariant during a scheduling lifetime; drift closes
admission without repair. Same-epoch idle resume additionally compares the
parked physical set and compute configuration. Every published engine's
private store must retire and validate before userspace epoch publication.
The detailed contract is in `spec.md` §3. Later checkpoints below add dynamic
client-free sysfs mode changes, width-one load balancing, bounded single-row
width-two through width-four groups and placement matrices.

### GT runtime, presentation and recovery foundations

Section 20 tracks completed profiles and open exit conditions.
Native models and kernel diagnostics remain implementation evidence; physical
acceptance and complete acceleration require their separate gates.

The owned GT API adds acknowledged GuC SLPC frequency bounds and
Base/PowerSaving profiles through the owned GT API (`intel_gpu_slpc`).
Stable main-GT RPn/RPe/RP0 discovery bounds requests before allocation;
range updates require matched replies and a final firmware readback. Pending
updates publish no confirmed status. Optional control failure retains the
shared buffer until verified stop and leaves command scheduling available.
BMG G21 keeps the source's 1200 MHz floor; graphics IP 20.01 conservatively
keeps the 2133 MHz MERT cap until the MERT/host-L2 owner removes it (§20).
Wa_22019338487 does not apply to MTL graphics.

Presentation now has a separately owned GGTT window/latch component
(`intel_gpu_scanout`), with object retention through fresh flip-done,
SURFLIVE and a changed stable frame count. Legacy console mappings are
restricted to their four 32 MiB pipe windows; GEM windows occupy 160–256 MiB,
below the GT arena. Failed writes, timeout and drop retain uncertain DMA
owners until independently verified fetch stop. The production KMS service
now installs this owner for fixed-mode Pipe A flips on MTL/Arrow with a live
GuC backend. It drains console CPU epochs, inhibits PSR, excludes legacy
modeset/PM and retains old/pending objects through fresh hardware latch
proof. State, events and out-fences publish together after that proof;
unsupported pre-arm states restore the console and use checked copy with
hardware vblank completion. NONBLOCK now publishes an owned FIFO job and
returns before dependency waits or latch; native out-fences carry terminal
success/error, and events require hardware completion. Inherited extra
planes/cursors, FBC and DSB refuse direct takeover. Automatic GT recovery
quarantines active display owners before reset, then uses fresh GT policy
and a verified console latch to retire their mappings. Failed recovery retains
them and keeps display admission closed. System suspend restores the console
before power teardown. Gen12 fixed-mode direct flips and the X/Tile4 layouts
are §20; compressed layouts remain open. The detailed contract is in `spec.md`
§3, "Intel GEM framebuffers".

After the GT's execution probes, the physical worker attempts single-vector
MSI for primary GuC, RCS0, BCS0 and BMG BCS8, preserving unrelated enable/mask halves.
The hard handler masks/posts the tile master; bounded task-context identity
decoding acknowledges only owned RCS0/COPY0/BMG-COPY8/OTHER0 causes before rearming. Dispatch
epoch capture precedes servicing, avoiding lost wakes around waiter polling.
The actual GuC/retirement path runs on the IRQ or a 10 ms watchdog; refused or
failed IRQ routing retains the 500 us timer path. Unrelated display/media
status is left pending with delivery closed. Reset/S3 tears down routing while
powered, and unprovable shutdown quarantines the vector/cookie instead of
reusing it. Active firmware routes and VMD shared routing refuse takeover;
ARM production routing still needs an ITS event owner. These native models do
not establish physical MSI delivery or Mesa/silicon acceptance.

Xe MAP_USERPTR is admitted with snapshot pins: the syscall boundary faults the
range, resolves write COW copies and retains `UserPagePin`s that every mapping
and job holds through retirement, so the GPU never reaches freed memory. Fork
copies pinned private pages for the child (`page_needs_cow_for_dma`), so the
pins keep aliasing the binder's memory. Each binding also registers a
memory-layer interval notifier, and EXEC re-collects or drops an invalidated
binding (`xe_userptr.c` invalidation/repin/rebind; see the USERPTR subsection
of §20). amdgpu GEM_USERPTR still uses snapshot pins only.

iGPU `DRM_XE_GEM_CPU_CACHING_WC` objects are admitted (MIT Linux
b90c984d615e8ce2af96f5b1411a962d83fed2ad `xe_ttm_tt_create`,
`xe_gem_create_ioctl`, `xe_vm_bind_ioctl_validate_bo`). Their pages come
from `narf_memory::pageattr::WcPages`: every kernel alias is retyped
write-combining before publication (TTM `set_pages_array_wc`), user mmaps
are WC, kernel copies end with SFENCE and device publication needs no
CLFLUSH. Pages are restored write-back only after the last mapping, VM
binding and job drop the object. SCANOUT is admitted on the iGPU and is
EINVAL with WB caching. XE_COH_NONE binds (MTL PAT1 WT, PAT2 UC; Gen12 and
DG2 PAT1 WC, PAT2 WT, PAT3 UC; MTL PAT0; every non-coherent Xe2/Xe3 entry)
are EINVAL for objects created with WB CPU caching and for USERPTR;
discrete WC objects and VRAM qualify (`bo->cpu_caching`). Compressed
Xe2/Xe3 indices are EINVAL for USERPTR and NO_COMPRESSION objects; reserved
indices and those past `n_entries` are EINVAL for every map, NULL included.
dGPU system memory stays WB as in Linux. aarch64 refuses WC
creation (`NotImplemented`): the kernel's linear map cannot be retyped.

Hung user jobs are recovered per context (MIT Linux
b90c984d615e8ce2af96f5b1411a962d83fed2ad `guc_exec_queue_timedout_job`,
`xe_guc_exec_queue_reset_handler`, `xe_lrc_timestamp` and `check_timeout`).
A user job's 5 s watchdog starts at GuC's enable ACK, but timeout attribution
uses the ring's CTX_TIMESTAMP/start-stamp stores and saved LRC runtime.
A private restore batch marks active state; live MMIO is sampled only when
RING_CURRENT_LRCA names that LRC before and after the read, with a saved-state
reread covering switch-out. Queuing and preemption consume no job runtime.
Unsigned 32-bit subtraction handles counter wrap, with Linux's 5% scheduling
tolerance. Two unchanged active timestamp samples also identify a hang.
Missing/unchanging inactive timestamps instead require full GT reset after the
entire engine makes no GPU progress for three watchdog intervals. Changed
sampled counters and completed breadcrumbs refresh that engine watchdog, so
no queue is blamed for a scheduling stall. Cache/read failures fail closed and
retain all backing until proven reset.

When a context exceeds its GPU runtime budget, the scheduler disables that
context alone; GuC preempts it or, if it cannot preempt within the
500 ms policy timeout, resets the engine and sends
CONTEXT_RESET_NOTIFICATION (0x1008). GuC also resets autonomously when a
non-preemptible context blocks a waiting one. Either way the context is
deregistered and its final TLB invalidation proven before its tables and
BOs are released; its saved state is never captured, its fence fails with
`JobError::Hang`, and its context is banned and counted guilty (i915
GET_RESET_STATS `batch_active`). Xe EXEC on a banned queue is ECANCELED
before syncs are parsed, after the queue lookup and batch-count checks, as
in `xe_exec_ioctl`. A job that completes while being disabled retires
normally. Kernel jobs, a reset notification for a kernel context, a second
expiry, an unanswered disable and ENGINE_FAILURE_NOTIFICATION still require a
full GT reset. Kernel jobs and protocol/retirement steps retain bounded
wall-clock deadlines. Native tests cover active/inactive samples, counter
wrap, switch-out and sentinel collisions, queued time, isolated recovery,
failed cache reads, engine stalls and continuously completing short jobs.

The scheduler now recycles a round-robin pool of 64 GuC IDs after verified
retirement, removing the 65534-request lifetime limit. Request stamps and TLB
cookies are independent of those IDs; wrap skips live stamps and old
generation-bearing evidence cannot retire a replacement job. The seed ID stays
leased through the forced switch/capture sequence. As in Linux Xe, ID-only
scheduling responses rely on GuC's deregistration contract; the final TLB ACK
also proves our reclamation barrier. Failed stop/capture retains leased IDs.

Graphics APIs, shader compilation and application state generation belong in
userspace; the kernel must supply the supported execution and memory contracts.

## 20. Software completion campaign

This section tracks the Intel software features beyond §19: the ledger
below, then the per-feature records. Intel silicon, physical link
qualification and Mesa execution acceptance remain separately recorded
evidence gates.

A feature closes only after its production entry point, resource lifetime,
reset/suspend behavior and refusal paths are implemented, its public contract
is documented, and relevant native tests pass. Architecture-neutral changes
use x86_64 regression tests by default; rerun aarch64 tests when its code or
behavior is affected. Cross-target builds and lint checks still verify shared
code portability. This iteration policy follows the maintainer's direction
to avoid redundant aarch64 test runs.
A query bit, codec, read-only audit or register model alone does not close a
production feature. Unsupported functionality remains unadvertised.
Every deadline-polled wait evaluates its condition before enforcing the
deadline, as i915 `__wait_for`, `xe_mmio_wait32` and `read_poll_timeout` do:
a late poll that finds the condition met progresses instead of timing out.

| Workstream | Software exit condition | State |
| --- | --- | --- |
| Nonblocking presentation | Owned bounded FIFO; immediate NONBLOCK return; native out-fences/events after latch; failures, close and reset retire queued work without fake success | Implemented; native fixtures pass |
| Display reset recovery | Fresh post-reset console latch independently retires old GEM fetch; clear failures retain owners; status/epoch ownership preserved | Implemented; native fixtures pass |
| First-error diagnostics | Bounded immutable per-card reports captured before isolated/full reset; stable read-only exposure and explicit unavailable data | Implemented; native fixtures pass |
| Userspace SLPC policy | Bounded sysfs mailbox; live-epoch admission; acknowledged range/profile publication; confirmed policy replay after resume | Implemented; native fixtures pass |
| BMG COPY1 | Physical BCS8 scheduling, shared-class ADS, per-instance saves/defaults, IRQ policy, PPGTT startup proof and native Xe/i915 selection | Implemented; native fixtures pass |
| Pipe-A CTM | Fixed-mode MTL/Arrow CTM-only commits, retained blobs/original state, latch evidence, cancellation and full console restoration | Implemented; native fixtures pass |
| Passive GuC logs | Default-off CAP_SYSLOG-gated read-only descriptors; bounded immutable raw snapshots with actual firmware identity and live ownership checks | Implemented; native fixtures pass |
| Cached dGPU sensors | DG2/BMG cached temperatures, DG2 voltage/extended energy, live-epoch admission and stale/loss refusal without read-triggered MMIO | Implemented; native fixtures pass |
| Boot-selected multi-CCS | Frozen fuse-qualified N-way partition; sparse physical/dense logical mapping, per-instance ownership and startup execution proofs; exact clean-resume identity | Implemented; native fixtures pass |
| Native gamma activation/bypass | 1024-entry Pipe-A LUT, owned copies/blobs, safe inactive preload, preserved flips and later-frame restoration | Implemented; native fixtures pass |
| Extended dGPU controls/telemetry | Bounded admin-gated DG2 PL1 actor with retained boot ceiling/readback, cached fan RPM and owned BMG thermal discovery | Implemented; native fixtures pass |
| Compatibility dispatcher | Exact Xe-first wire routing on live GuC cards, shared WB GEM/PRIME/syncobj identity, observed discovery/SSEU and WB-only compatibility cache/mmap/softpin policy | Implemented; native fixtures pass |
| VM/address mirrors | USERPTR invalidation/MMU notifier, i915 GEM_USERPTR, fault-mode/CPU mirrors and separately qualified nonfault long-running VMs | Open; memory/ interval notifiers landed (non-blocking callbacks fired by every translation change, pins bound device access) and Xe MAP_USERPTR re-collects, rebuilds or drops invalidated bindings at EXEC with native fixtures added (§20). Swap, lazy-free and compaction now refuse pinned pages, and VRAM CPU mappings are revoked and refaulted across runtime suspend (§20); i915 GEM_USERPTR (`i915_gem_userptr_ioctl`) and the Xe LR_MODE/FAULT_MODE VM flags with PREFETCH are admitted ("Completion of Intel iGPU and Discrete Arc Support"); CPU-address-mirror VMs remain |
| Local-memory management | Nonvisible allocation beyond the exact opted-in BMG headless profile; eviction/migration, alias revocation and preserved auxiliary system representations; dynamic dma-buf importers and in-place suspend of pinned VRAM exports | Open; DG2/BMG evict VRAM to system memory (flat-CCS saved) and migrate it back, evict under OOM at GEM_CREATE, re-migrate at exec and drain for suspend ("Completion of Intel iGPU and Discrete Arc Support"); CPU mappings of the BAR window are revoked while runtime-suspended and refault through resume (§20); DG1 publishes VRAM below `GSMBASE` (§5); cross-device VRAM PRIME runs with static attachments, and peer-to-peer behind `narf.intel.prime_p2p=1` (§19), unvalidated on hardware. Dynamic (move-notify) importers, in-place suspend of a pinned VRAM export, alias revocation and nonvisible allocation beyond the BMG headless profile remain |
| Client-free CCS reconfiguration | Card-lifetime primary/render leases; admin-gated asynchronous reset, all-engine startup proofs and fresh-epoch publication | Implemented; native fixtures pass |
| GuC width-one load balancing | Same-class placement mask, private per-restore hardware engine receipt, migration-aware watchdog, retained LRC/VM/retirement ownership | Implemented; native fixtures pass |
| i915 virtual contexts | LOAD_BALANCE proto-map extension through the production GuC backend, copied distinct same-class placements, transactional namespace and migration/retirement ownership | Implemented; native fixtures pass |
| GuC width-two through width-four groups | Single-row adjacent dense logical COPY/COMPUTE/VIDEO (VCS/VECS) lanes, protected scratch/workqueue, contiguous IDs, independent saved/runtime state and all-lane retirement | Implemented; native fixtures pass |
| Engine scheduling | Additional platform-qualified queue protocols and protected queues with their firmware/security dependencies; pinned source gives current platforms no CGP class mask | Open; independent capability/firmware qualification. Multi-lane parallel queues (width > 1) supported for Copy, VCS, VECS, and Compute engines (classes 1..=4). Protected queues: without `narf.intel.pxp=1` PXP_TYPE, the PXP status query and BO PXP_TYPE refuse with Linux's no-PXP errnos (HWDRM ENODEV, NONE accepted); with it, MTL/Arrow HWDRM queues, objects, CHECK_PXP binds and the status query follow Linux's enabled-PXP paths (see "MTL/Arrow PXP behind narf.intel.pxp=1"), with native fixtures only. GSCCS0 is now a kernel-only (reserved) engine of the MTL/Arrow media GuC under both media and GSC options, never queryable or placeable |
| Media GT | Independent firmware/wake/cache/CT owner, VCS/VECS scheduling and HuC loading/authentication | Open; opt-in MTL/Arrow GT1 runs its own media GuC, schedules fused VCS/VECS with media-only ADS, default LRCs, CT GGTT invalidation and routed interrupts, and publishes native Xe gt_id 1 after per-engine private-PPGTT jobs retire, including GT1 engine-cycles and topology (with GT1's L3 bank entry) queries; with `narf.intel.huc=1` its media GuC DMA-loads and authenticates the MTL HuC and query7 type1 reports it; GT1 runs GuC SLPC from its own media fuses, GuC RC6 and powergating before publication (a failed start stops GT1, as xe_uc_load_hw fails) and returns RC6/powergating to the host before every stop; with `narf.intel.gsc=1` the media GuC's stop honours Wa_14015076503, GSCCS0 is scheduled beside VCS/VECS, the GSC private object lives in a device-lifetime stolen claim behind a fixed GGTT DM window, and the runtime runs the GSC worker: firmware load, compatibility query and HuC authentication via the GSC, then the proxy channel once the MEI GSC proxy component (drivers/platform) is bound, else Linux's tolerated ENODEV. Media-GT OAM Unit 1 streams with MPEC formats and VCS/VECS exec queues, and GT1 frequency/idle sysfs (`gt1/` and `tile0/gt1/{freq0,gtidle}/` with live `MTL_MEDIA_MC6` residency and `MTL_MIRROR_TARGET_WP1` CAGF readout) implemented with native fixtures. The MEI GSC proxy client is in drivers/platform; with `narf.intel.pxp=1` GT1 also runs Xe PXP (KCR, the ARB session through the GSC, terminations on IRQ, GT1 stop and resume) with native fixtures. Silicon acceptance remains |
| Diagnostics/performance | Full coredump/error-sysfs and batch capture beyond bounded native/i915 selected payloads, qualified log fanout, OA, additional sampling platforms and remaining i915 perf/SSEU/parameter interfaces | Open; opt-in (`narf.intel.oa=1`) main-GT OAG streams on DG2, MTL/Arrow, BMG and LNL implemented with native fixtures: query 8, ADD/REMOVE_CONFIG, open, ENABLE/DISABLE/CONFIG/STATUS/INFO and read/poll with source errno order, kernel-ring LRI configuration, landing/wrap/status handling and reset/suspend teardown; opt-in (`narf.intel.devcoredump=1`) GuC error-capture lists, STATE_CAPTURE extraction/matching, the manual timeout fallback and the version-4 coredump text (header, exec-queue policy, job batch addresses, HW-engine registers) implemented with native fixtures; OA mmap (read-only private PFN mapping with VM_DONTCOPY/VM_DONTEXPAND semantics in the syscall layer), `metrics/<uuid>/id`, `dev.xe.observation_paranoid` and i915 GETPARAM 57 implemented; legacy i915 perf UAPI compatibility (PERF_OPEN, ADD_CONFIG, REMOVE_CONFIG, stream ioctls ENABLE/DISABLE/CONFIG, sample header prepending, query item 3 DRM_I915_QUERY_PERF_CONFIG, GETPARAM 54 PERF_REVISION) implemented with native fixtures; OA syncs (`DRM_XE_OA_CAPS_SYNCS`, in-fence waiting, out-fence and user-fence release on stream open and CONFIG), media-GT OAM UAPI coverage with synthetic independent GT owners (MPEC formats 8/9, VCS/VECS mapping, concurrent stream permits), and parallel queue creation across Copy, Compute, and Video engines (classes 1..=4) implemented with native fixtures; OAR/OAC exec-queue streams with per-context OAR/OAC programming at enable/disable retiring on the bound queue through the trusted-submit-on-user-context entry point, RING_CONTEXT_CONTROL reaching the queue's saved state, implemented with native fixtures; steered manual capture and the coredump's wall-clock snapshot time and guilty process name implemented with native fixtures |
| Atomic display | General watermark/DBUF/CDCLK/pcode transactions, multi-pipe and bigjoiner, DSC and VRR, tiling/compression beyond qualified X/Tile4 profiles and additional planes | Open; display14 resource transactions landed: all-pipes-off owned Pipe-A entry, live repartitioning, the Pipe B-D owner (production caller: the MTL external route; pipe-DMC bracket and IRQ-masked evasion around every arm; the display-14 crtc registers of hsw_crtc_enable; the all-off post-plane lowering after the last release) and SAGV with QGV derating; the fixed Pipe-A KMS owner proves its share of the published multi-pipe layout, so flips, the cursor, color/DSB, Tile4/XR30 and PSR keep working beside a lit external; display-14 DSC landed (the eDP panel compresses when Linux would and external DP compresses with FEC, with the VDSC CDCLK and prefill terms in the resource transaction and read back by every later proof); display-14 6 bpc pipes landed (EDID bpc and VBT `edp.bpp` limits, 18 bpp before DSC, dithered `PIPE_MISC`, BPC_6 and the 6 bpc MSA on Pipe A and Pipes B-D); ADL-P/N write display 13's `TRANS_VBLANK`; the display-14 pipe-scaler panel fitter (`XeLpgModeset::with_panel_fit`, aspect/center/fullscreen scaling, filter selection, `PIPE_SRCSZ`, `SKL_PS_*`, sized framebuffer validation) and bigjoiner master/slave programming (`XeLpgModeset::with_bigjoiner`, `ICL_PIPE_DSS_CTL1` master/secondary joiner enable, watermark scaler prefill lines) wired with native fixtures; VRR foundation landed (#1768): honest sink capability (DPCD Ignore-MSA + EDID range spread > 10 Hz, VBT vrr gate for eDP, per-connector vrr_capable published instead of the hardcoded Some(true)), vrr_enabled in atomic CrtcState forcing a full modeset on toggle (Intel only), and per-modeset VRR timing recompute from the committed mode + sink range (Linux vmin-from-max_vfreq / flipline semantics, vmin>=vmax / interlace / joiner bails, late guardband phase + Gen12 pipeline_full). VRR readback landed (#1772): GOP-left state decoded into VRR_STATE at install/modeset setup, fixed-RR TGs disabled (CMRR exempt), reconciled enable surfaced to the atomic Card::vrr_enabled slot. VRR sequencing landed (#1769): VRR timings programmed in the Gen12 and Xe-LPG (non-Xe3) modesets from the committed mode + stored sink range (`intel_vrr_set_transcoder_timings` during transcoder configuration), TG enabled after the transcoder (`intel_vrr_enable`), VRR disabled before the transcoder stop (`intel_vrr_disable`, timed 1000 ms wait surfacing `TimedOut`, `TRANS_VRR_VSYNC` cleared on AS-SDP displays), push writes `TRANS_PUSH_EN | TRANS_PUSH_SEND` with an `is_push_sent` readback, `on_plane_flip` takes the CRTC from the owning display instead of hardcoding 1, and `request_vrr_enabled` returns hardware failures instead of swallowing them (the request stays retained in `VRR_STATE` for the next modeset when the controller is not up or no timings are stored).. CMRR landed (#1771): `is_cmrr_frac_required` tolerance check (0.10 Hz, Linux `intel_vrr.c`) + eDP auto-enable in the per-modeset compute with the built-in-panel modeset wired in (no sink range required — eDP discovery publishes none yet), `CmrrTimings::compute` reconciled with Linux `cmrr_get_vtotal` (derived vtotal, /1001 video multipliers resolving Linux's open TODO), and CMRR stays sysfs-only for manual control (no DRM-visible control — Linux has no CMRR property) DPCD+PSR landed (#1770): DPCD MSA-ignore programming (`DP_DOWNSPREAD_CTRL` 0x107 bit 7, read-modify-write preserving SSC, sink-advertised + not fixed-RR, synced on VRR/CMRR toggle and every Pipe-A modeset) and PSR×VRR mutual exclusion (PSR refused while the VRR TG runs variable-rate, fixed-RR TG relaxation via CMRR, re-evaluated at every latch since the refusal is not latched, SCL floor 1 with the VRR TG per wa_14015401596 with the guardband computed against it) |
| Output support | MTL external-display admission, Type-C/Thunderbolt PHY and alt mode, HDMI 2.1, DP UHBR, owned hotplug, qualified PSR2/panel replay | Open; MTL DP SST on DDI B/TC DP-alt and HDMI TMDS (DDI B, VBT-declared legacy Type-C; HDMI 2.0 scrambling/SCDC to 594 MHz; YCbCr 4:2:0 on display 14/20) runtime-wired through one hotplug service on Pipes B-D beside the lit panel (live resource repartition, PM demand at the route port clock, pipe published with the image), Type-C ownership, owned PICA/south hotplug and display-14 AUX power implemented with native fixtures; VBT port facts (OpRegion VBT: ports, legacy Type-C, DDC pins, DP SSC; Gen12 DDC pins) and Gen12/MTL E-DDC implemented with native fixtures; DC-state join implemented; PSR1 on the KMS-owned MTL/Arrow Pipe-A eDP implemented (§20) with the display-14 watermark provider (Wa_14015648006) and the VBT PSR gate and wake times, so it can enable on hardware whose VBT enables PSR for the panel and whose Pipe-A watermarks are the owned modeset's; panel KMS flips, cursor, color/DSB and PSR keep running while an external is lit (the external pass brackets Pipe A with the FBC/PSR pre/post plane updates and idles an in-flight panel DSB); eDP DSC on the panel and DP DSC with FEC on Pipes B-D implemented with native fixtures (§20); PSR2 with selective fetch on that panel implemented (§20), driven by FB_DAMAGE_CLIPS and DIRTYFB damage and falling back to PSR1 with a typed reason; 6 bpc eDP and DP outputs and `DP_LINK_RATE_SET` training of display-14 eDP rate-table panels implemented with native fixtures (§20); the MTL/Arrow panel's full crtc disable and enable (PPS, DDI, PLL) and Linux's link-training fallback ladder on the panel implemented with native fixtures (§20); DP-alt pin D, native/legacy board reversal, live TBT DP-IN display routing and display-14 MST now have native implementations (USB-C display checkpoint below); HDMI FRL, UHBR, a second independent concurrent external route and Panel Replay remain open |
| DSB color transactions | Fixed progressive MTL/Arrow Pipe-A active LUT replacement and joint primary/CTM/gamma arms; retained command/primary mappings, dual hardware witnesses, cancellation/restoration markers and independent DMA retirement | Implemented; native fixtures pass |
| Linear primary panning | Fixed MTL/Arrow visible geometry/stride, bounded integer source viewport, aligned SURF/residual OFFSET in common DSB arm and full console/reset retirement | Implemented; native fixtures pass |
| Full-AUX panel backlight | Qualified MTL/Arrow VESA eDP caps/mode/width, arbitrated live-route AUX owner, retained brightness intent and verified panel suspend/relight | Implemented; native fixtures pass |
| Display services | Display runtime PM/DC states/DMC, FBC, broader color profiles/transforms, HDCP and Arc display | Open; MTL/Arrow DMC, DC_off references and lit-panel DC5/DC6 implemented (§12.1, native fixtures added); FBC on the fixed MTL/Arrow Pipe-A primary for KMS-owned GEM framebuffers only, with a CFB placed in DSM excluding WOPCM, the GSC region (only with a Wa_14019821291 media GT) and boot-framebuffer pages, proven outside system RAM, carved by a chunked off-present-path job (FBC stays off until it finishes); PSR wins over FBC while enabled (PSR1: Wa_14016291713, no stepping readout; PSR2: selective update refuses FBC); an external repartition deactivates FBC before and re-activates it only on a re-proved Pipe-A layout after the latch (same CFB); MTL/Arrow panel off/on (atomic `ACTIVE=0`, `SETCRTC` off, `FBIOBLANK`, master release) with PSR and FBC disabled first and the backlight sequenced (§20); HDCP 1.4 and 2.2 on external SST DP and HDMI (display 12+; MEI firmware on 12/13, GSC on 14+) with the "Content Protection" / "HDCP Content Type" connector properties behind `narf.intel.hdcp=1` (§20, native fixtures added, no silicon run); Gen9 and Gen9 LP DC states behind `narf.intel.gen9_dc=1` (§12.5) and the display-20/30/35 DC services (§17, §5); DG2/BMG KMS over a firmware-lit Pipe A ("Completion of Intel iGPU and Discrete Arc Support"); broader color, DP MST HDCP and Arc display beyond that remain |
| BMG package PL1 | Shared PCODE owner; passive firmware defaults, admin-gated pair-preserving write and exact current-source readback | Implemented; native fixtures pass |
| BMG PMT energy | Qualified bounded BAR0 PUNIT discovery and exclusive remapper owner; cached checked card/package energy, units/wrap and loss/reset handling | Implemented; native fixtures pass |
| Additional hwmon controls | BMG firmware-selected I1 thresholds, paired PL1/PL2 and both intervals; DG2 PL1 intervals; fresh observations/readback, retained ceilings and fair shared PCODE transaction ownership | Implemented; native fixtures pass |
| GuC LFD export | Protected immutable source-format export, checked LIC/event/crash framing, shared raw-snapshot permits and capability revocation | Implemented; native fixtures pass |
| Automatic GuC failure bundles | Preallocated immutable first-failure report/log/CT copy, live access/coherence proofs, protected descriptors, generation-matched clear and two-buffer limit | Implemented; native fixtures pass |
| PRIME explicit-fence import | Shared same-card reservation, actual fd/flag validation, foreign callbacks/drops outside locks and generation-checked CPU/implicit admission | Implemented; native fixtures pass |
| DG2 visible VRAM | Stable layout, 64 KiB placement/PS64 groups, real BCS0 data and flat-CCS initialization before publication, cancellation/reset ownership and fallback | Implemented; native fixtures pass |
| Fixed hardware cursor | Qualified MTL/Arrow Pipe-A 64x64 legacy cursor, owned PM_DEMAND/DBUF/MBUS/watermarks, private permanent slots, FIFO writer waits and independent cursor/DSB retirement | Implemented; native fixtures pass |
| GuC flush-coordinated streaming | Independent admin/syslog opt-in, two-frame event/crash FIFO, copy-before-cursor/ACK, observed-loss refusal, acknowledged policy restoration and reset quarantine | Implemented; native fixtures pass |
| Parallel GPU user-fence joins | Parent GGTT waits on every child, one PPGTT qword store, private final marker, independent payload and final-join watchdogs and all-lane retirement | Implemented; native fixtures pass |
| Legacy Intel gamma | Actual 256-entry 8-bit palette, copied GET/SET ramps through owned KMS FIFO, duplicate posted DSB writes, hardware-confirmed store and original-palette restoration | Implemented; native fixtures pass |
| BMG whole-card PSYS controls | Paired PL1/PL2 and intervals through fair shared PCODE owner, independent retained ceilings, explicit source switch and exact whole-pair readback | Implemented; native fixtures pass |
| BMG EU-stall sampling | Default-off privileged Xe observation, real sparse-DSS MCR buffers, bounded host FIFO, copy-before-ack, loss reporting and reset-owned DMA lifetime | Implemented; native fixtures pass |
| GuC placement matrices | Distinct adjacent rows, immutable per-lane masks, every-restore physical receipts, migration watchdogs and all-lane final capture/retirement | Implemented; native fixtures pass |
| Pipe-A pre-CSC degamma | Exact 129-entry equal-channel monotonic LUT, source 24-bit/131-word programming, triple-blob FIFO/DSB ownership and original-state restoration | Implemented; native fixtures pass |
| EU-stall read thresholds | Full physical threshold range, bounded preallocated host capacity, sampled readiness latch and current per-invocation blocking/nonblocking status across scalar/vector/positioned reads | Implemented; native fixtures pass |
| Retained execution coredumps | Preallocated version-two failure bundles with eight bounded LRC/ring/group-scratch slots, host-only lane identity, explicit missing/truncated data and unchanged reset ownership | Implemented; native fixtures pass |
| Privileged Xe HIGH priority | Current CAP_SYS_NICE creation/publication, caller-aware CONFIG maximum, immutable GuC priority 1 through physical/virtual/parallel execution and retained reset ownership | Implemented; native fixtures pass |
| Dumpable VM/BO coredumps | Frozen DUMPABLE ranges, allocator-owned table pages, bounded system/WC/USERPTR prefixes, explicit unavailable/truncated data and unchanged job retirement | Implemented; native fixtures pass |
| Fixed X-tiled primary | Qualified MTL/Arrow no-DPT/resource profile, WC XR24 tile layout and integer panning, modifier discovery, common DSB arm and independent linear-console/reset restoration | Implemented; native fixtures pass |
| BMG MERT/host-L2 coordination | Mandatory source-qualified bootstrap/actual-frequency/MCR/flush proofs, acknowledged cap removal, GT-retained CPU-VRAM clears and fresh flush tickets, post-reset cap/disable before wake release | Implemented; native fixtures pass |
| Trusted GPU range copies | DG2/BMG retained private BCS0 copy jobs, atomic reservations, local data/CCS ownership, cancellation and full-reset retirement | Implemented; native fixtures pass |
| PCI runtime policy controls | Current admin/epoch sysfs actor, core forbid/auto/signed delay, cached enabled-PM accounting and cancellation-safe disable | Implemented; native fixtures pass |
| Fixed Tile4 primary | Qualified MTL/Arrow layout/panning with source watermark equations, retained original/current/pending images and joint DSB/primary/console retirement | Implemented; native fixtures pass |
| Fixed opaque XR30 primary | Qualified MTL/Arrow LINEAR XR30 input, epoch-bound metadata, projected FIFO, common DSB/primary witnesses and retained original-console restoration | Implemented; native fixtures pass |
| Gen12 GuC execution | Exact firmware families, optional HWCONFIG, source cache/context/restore policy,39-bit DMA, RCS0/BCS0 native execution, owned reset and non-tile MSI | Implemented; native fixtures pass |
| Gen12 fixed internal primary | Live exclusive GT, unchanged bandwidth/route/resource image, PAT-free bounded mappings and native FIFO/cancel/reset/console proof | Implemented; native fixtures pass |
| Gen12 fixed CTM | Driver-established internal RGB bypass, retained route/resource/console proofs and native queued CSC latch/restoration | Implemented; native fixtures pass |
| Gen12 fixed hardware cursor | Source PCODE/DBUF watermark partition, private PAT-free DMA39 slots, generation-specific DSB and independent cursor/console retirement | Implemented; native fixtures pass |
| Gen12 native and legacy LUTs | Exact display12/13 gamma/degamma profiles, bounded ABI/storage, canonical DSB writes, readable state witnesses and profile-specific original restoration | Implemented; native fixtures pass |
| GuC loss-accounted log fanout | Four bounded reader FIFOs, transactional host loss accounting, observed firmware-overflow lower bounds and actual publication/incarnation-bound admission | Implemented; native fixtures pass |
| Gen12 joint primary/color | Fixed retained common DSB transactions, full inactive preload where required, independent primary/color retirement and shared native-frame publication | Implemented; native fixtures pass |
| Gen12 X/integer primary views | Exact family SURF alignment/control, fixed source X/linear viewport bounds, old/pending journal and exact original-console recovery | Implemented; native fixtures pass |
| Headless LNL main GT | Exact PCI/GMD/firmware profile, one-way boot exclusion, fresh whole-device reset/media arena, five-level private VM and all-engine probes | Implemented; native fixtures pass |
| Headless PTL main GT | Exact Xe3-LPG IP/step/PAT/cache/context/SLPC, retained takeover, 96-DSS physical topology and all-engine private-VM probes | Implemented; native fixtures pass |
| Gen12 main-GuC media | Fuse-present VCS/VECS defaults, source video commands, retained media wake/reset/ADS/IRQ and actual native Xe queues | Implemented; native fixtures pass |
| Legacy i915 media selection | Live published BSD/VEBOX discovery, dense sparse-engine selectors and retained independent per-context state through real GuC execution | Implemented; native fixtures pass |
| Intel CPU alias lifetime | Whole-BO physical census, pending publication tokens, retained unpublished-fork metadata and permanent mixed-vendor provider dispatch | Implemented; native fixtures pass |
| Xe low-latency queue hint | Truthful current ABI/epoch discovery, immutable real queue flag, source policy KLV before enable ACK and retained physical/virtual/parallel contexts | Implemented; native fixtures pass |
| LNL EU-stall observation | Exact headless graphics20.04 profile, retained sampler/cache/media proof and existing bounded privilege/loss/reset lifecycle | Implemented; native fixtures pass |
| Retained Gen12 external SST stop | Current observed combo-B HPD, fresh status incarnation, checked retained local-stop/publication/PM gate and exact implemented-plane inventory | Implemented; native fixtures pass |
| Per-object i915 ASYNC | Live BMG ordinary WB softpin and same-card WB imports, truthful GETPARAM43, selective prior GPU waits, atomic mixed admission and retained terminal/CPU ordering | Implemented; native fixtures pass |
| Exact-TGL HuC upload/auth/query | Default-off actual firmware/BO/WOPCM, both-pass DMA, typed zero-result CT plus fresh status, current Xe query7/type1 and full-reset reclamation | Implemented; native fixtures pass |
| i915 context frequency hint | Cached exact GETPARAM59 ABI, proto/create-only immutable intent, retained real GuC policy and private nonce-bound context publication | Implemented; native fixtures pass |
| BMG opt-in GPU-only VRAM | Exact headless small-BAR takeover, immutable hidden backing, trusted GPU zero/copies, retained quota and off-lock exact-VM publication | Implemented; native fixtures pass |
| i915 selected capture and protection | Actual retained WB/import payload prefixes, cached GETPARAM45 and source-live per-context whole-bundle suppression | Implemented; native fixtures pass |
| i915 automatic global-reset availability | Cached GETPARAM35 level1 only with a distinct current worker/every-engine qualification witness and retained stop/requalification policy | Implemented; native fixtures pass |
| i915 context priority | map_i915_prio_to_guc_prio at every registration (default KMD_NORMAL2), request-time priority with same-context in-flight raises as priority-only UPDATE_CONTEXT_POLICIES, advertised I915_SCHEDULER_CAP_PRIORITY | Implemented; native fixtures added, unexecuted |
| GT power/telemetry | D3cold, safe autosuspend with live mappings/panel, additional flush consumers/platforms and media power | Open. MTL/Arrow and Gen12 owners arm autosuspend. Lit pipes, display-14 `DC_off` references and the DC re-entry hold display wakerefs (RPM usage references), so a lit panel keeps D0 (Linux display wakeref) and idles through DC5/DC6 (§12.1). A dark panel parks with the DMC retained and re-verified and with 10 s polled hotplug; atomic `ACTIVE=0`, `SETCRTC` off and `FBIOBLANK` turn the MTL/Arrow panel's crtc off and drop its wakeref, and a KMS commit resumes the function first (§20). System-memory mappings need no revocation (xe_bo.c). A discrete GT now runtime-suspends with VRAM allocated and mapped (BAR mappings revoked and refaulted, kernel copies gated, §20). D3cold refuses with a typed reason (no `_PR3`/platform power). Gen9/Gen11 frequency requests and RC6 run on the execlists owner (§12.5), and MTL/Arrow GT1 SLPC, RC6 and powergating on the media GT. D3cold through `_PR3` and further flush consumers remain |
| Additional platforms | Broader display/platform services beyond the fixed Gen12 and headless LNL/PTL execution profiles | Open; opted-in LNL display 20 has an owned eDP Pipe-A modeset with display-20 resources, a display-preserving GT owner (no driver FLR; GT-only GuC/full reset; D0-only), an owned console with the KMS owner's Pipe-A flips at Xe2 PAT3 (linear, and X/Tile4 through an owned power-of-two DPT), the display-14 cursor, CTM/LUTs and DSB with Xe2 PTEs, the Xe `SCANOUT` create flag, Wa_15015404425 on the probe-time modeset window, and the DC service loading `xe2lpd_dmc.bin` into DC6, plus PSR1, FBC, tiled panning, suspend/relight and external DP/HDMI (§17); PTL and WCL display 30 (`narf.intel.ptl_display=1`, `narf.intel.wcl_display=1`), Nova Lake-S display 35 (`narf.intel.nvl_display=1`, `narf.intel.nvl_modeset=1`), Gen9 LP and fixed-mode KMS on Gen9/Gen11 and MTL/Arrow desktops are driven (§5, §17); native fixtures only, silicon acceptance remains |

Changes to memory/VM or other TCB members carry the process-required safety
argument and security review.

The second parallel checkpoint adds these bounded production paths (Linux
reference `b90c984d615e8ce2af96f5b1411a962d83fed2ad`):

- BMG BCS8 is physical COPY8 and logical COPY1 throughout ADS, context saves,
  default priming, register policy, IRQ dispatch, startup execution proofs and
  both Xe and explicit i915 engine maps. Future USM ownership must reserve it.
- Fixed-mode MTL/Arrow Pipe-A CTM-only transactions retain 72-byte DRM blobs and
  the original color state. Full owned modesets establish and verify RGB bypass
  while Pipe A is off; live inherited adoption still refuses unsupported color
  state. Coefficients are programmed before the final CSC
  arm; readback and a later stable hardware frame prove completion. Full
  console release restores original state. Mixed CTM/framebuffer changes,
  gamma/LUTs and additional planes remain separate work.
- `/dev/dri/guc-logN` provides protected passive log retrieval, enabled only by
  one unambiguous `narf.intel.guc_log=1` boot argument and current initial-user-
  namespace CAP_SYSLOG at open and every read. Two immutable snapshots per
  card retain the exact owned raw BO and a NARF framing header with actual
  firmware release/digest/incarnation. Fresh reads never wake a sleeping GT;
  only live coherent backing is copied. Firmware bytes can contain GPU
  addresses/instruction state. Streaming, verbosity, flush/cursor consumption,
  lossless capture and full devcoredump remain open.
- DG2/BMG register a read-only `xe` hwmon node. The awake retained GT owner
  samples at most once per second, checking current D0/authority before each
  read; sysfs only reads the cache and stale/lost data is unavailable. Package
  and VRAM temperatures, BMG channel temperatures, and DG2 voltage/extended
  energy are supported. Writable controls, fan/mailbox limits and BMG PMT
  energy remain open.

The third parallel checkpoint adds source-qualified boot-only multi-CCS,
1024-entry native gamma activation/bypass, extended dGPU controls/telemetry and
immutable i915 discovery/default-SSEU query handling. Production GuC cards
continue to select Xe; this compatibility dispatcher work does not admit a
new legacy execution backend or close that production acceptance gap. It
uses the same pinned Linux revision.

Gamma activation is a bounded profile: active-to-different-LUT and simultaneous
changed CTM/gamma requests refuse, including TEST_ONLY. An explicit disable
then install is supported. A real DSB/early-vblank owner is required for live
replacement and jointly armed resources; the new properties alone do not
close full color parity. Original inactive palette/maxima are restored only
after bypass latch proof. Legacy gamma remains unsupported on this Intel path.

Multi-CCS owns only selected physical engines in GuC/ADS, while assigning all
present compute slices to them. This extends the previous mode-one subset,
without claiming ownership of unselected engines. Dynamic sysfs reconfiguration
still requires a client-free reset transaction. DG2 PL1 uses posted register
readback, not a firmware ACK, and cannot raise power above its retained boot
ceiling. BMG power mailboxes/PMT and writable fan/thermal controls remain open.
Read-only SSEU returns the legacy eight-bit default-context view, not a new
SSEU reconfiguration feature; full topology queries retain full masks.

Master handoff now retains a restoration marker for every installed native
Intel display owner, including non-color Gen12 profiles. The replacement
master's first hardware action and lastclose consume that marker under one
display Session; cancellation or failure cannot let stale color metadata or
a late close task overwrite a newer owner. Known telemetry access loss
also hides cached observations immediately between the 1 Hz sampling ticks.

The fourth parallel checkpoint connects client-free DG2/BMG CCS changes to the
retained GT reset owner. Card-lifetime primary/render leases include opens
before backend installation, duplicate file references and namespace teardown.
An accepted administrative request holds the open gate and runtime-PM usage
reference through full stop, rebuilding every selected engine, private PPGTT
execution proofs and fresh-epoch publication. Lastclose jobs still in flight
refuse reconfiguration without resetting. Loss/S3 retires even an otherwise
idle confirmed epoch; ordinary idle park preserves the existing resume policy.
The asynchronous status describes completion independently of the sysfs store.

BMG package PL1 now shares the existing fan/thermal PCODE owner. Passive
firmware-source reads establish cached defaults and the original ceiling;
they never switch policy. An explicit administrative request freshly reads
the pair, preserves PL2/time fields, writes PL1 and requires exact source-zero
pair readback. Status completion alone is insufficient. Close/reset discards
pending requests and source ownership without replay; known access loss hides
caches immediately and ambiguous ownership quarantines the shared port.
BMG PMT energy, writable fan/thermal and PL2/time-window controls remain open.

Fixed progressive MTL/Arrow Pipe-A active gamma replacement and joint CTM/
gamma changes now use a retained DSB0/DSB1 transaction. The main stream uses
hardware scanline evasion and color arms; the vblank-triggered leaf loads LUT/
clamps and reports completion. Live timing/VRR/DCB/PSR/DEwake checks precede
arming. Fresh leaf status, consumed heads, ordered engine disable, later-frame
and actual palette/control readback precede events, fences and Card publication.
The same per-function ledger checks console/primary/GT windows and exclusively
leases the command gap. One private 16 KiB WC BO and its GGTT address remain
pinned after exposure and are reused only after proven fetch retirement; there
is no unsupported global translation-invalidation claim. Timeout/loss retains
all command backing. GT reset, canceled waiters, replacement masters and fresh
console latches cannot bypass old DSB retirement. Color mixed with framebuffer/
mode/route changes and broader display profiles remain separate work.

The fifth parallel checkpoint extends the same pinned Linux source profile.
Width-one Xe queues accept a copied bounded same-GT/class placement list and
submit one persistent LRC with the full dense logical GuC mask. Firmware selects
the physical engine. A private ENGINE_ID receipt is written on every restore
before the active timestamp; sparse CCS and BMG COPY0/COPY8 decode actual
hardware class/instance separately from their GuC/UAPI numbers. Watchdogs use
current physical evidence and placement-group progress across migration and
preemption. Queued/unobserved work is not attributed to the template engine.
The existing disable/deregister/final-TLB and full-reset proofs retain virtual
context resources; parallel width greater than one remains refused.

Fixed-mode MTL/Arrow primary flips may now join CTM/gamma in one DSB transaction
when the target is direct linear WC SCANOUT XRGB with exact retained geometry.
The primary arm follows color arms in DSB0's safe window. Both the actual
primary flip-done/SURFLIVE and complete DSB/leaf/color proofs are required before
publication or old-window release. A persistent abandoned-mixed marker blocks
partial operations until joint publication or complete console restoration;
cancelling restoration retains it and both DMA owners. Copy fallback, scaling,
route/mode changes, tiled/compressed formats and extra planes remain open.

BMG card/package energy comes from its actual source-qualified BAR0 PUNIT
telemetry record through the GPU-owned remapper, with fixed 2^-14-Joule units and
independent checked 32-bit counter extension. Real BAR/descriptor bounds,
identity and selector readbacks are rechecked at every 1 Hz sample. Optional PMT
refusal leaves unrelated valid sensors; current D0/capability/epoch loss hides
all caches immediately. Reset/resume starts a fresh series. There is no
arbitrary endpoint/GUID mapping or invented PCI capability prerequisite.

Intel same-card PRIME now imports sync-file READ/WRITE leaf batches into its
shared reservation. The filesystem core captures immutable fence metadata,
observes status outside locks, publishes prepared batches without foreign
callbacks and retains removed references until admission locks are released.
CPU copies and implicit native admission require an unchanged addition
generation after their conflict observation. Racing imports therefore cannot
slip between validation and copying/publication. Xe GPU synchronization remains
explicit; existing raw CPU mappings still require caller exclusion.

The sixth parallel checkpoint connects i915 LOAD_BALANCE contexts to the
production GuC backend on both primary and render nodes. Full Xe command
encodings win; only the explicit supported i915 encodings reach compatibility
dispatch, sharing WB GEM/PRIME/reservation/syncobj identity with separate VM
metadata. VERSION remains xe through temporary loss. Proto-map extension
validation copies immutable distinct same-class placements before publication;
actual EXECBUFFER jobs use firmware engine selection, saved state, private
PPGTT roots and existing migration/retirement/reset ownership. Native WC/VRAM
handles cannot silently inherit the compatibility path's WB PTE/cache/mmap
policy, and VM-associated BOs cannot escape their unique native VM through
softpin. Bonding and parallel submission remain refused.

Fixed MTL/Arrow primary panning retains visible mode dimensions, stride,
linear XRGB format and destination0, with an integer source rectangle inside
the framebuffer and BO. The aligned SURF/residual OFFSET decomposition follows
the TGL+ 4 KiB linear rule; full mapped prefixes fit the 96 MiB reservation.
The linear watermark/DDB parameters remain unchanged. Panned PAGE_FLIP,
SETCRTC and atomic source updates use common DSB evasion/arming, both hardware
witnesses and queued/projected source x/y. OFFSET precedes SURF in that safe
window. Console/master/reset restoration proves OFFSET0 and the original
surface before releasing old DMA owners. Nonzero framebuffer byte offsets,
scaling, copy fallback and hardware cursor admission remain refused.

BMG I1 exports the firmware-selected card power or package current threshold
through a data-only PCODE write and exact mode/data readback. A retained
nonzero boot threshold is a conservative ceiling; no mode switching or silent
firmware clamp is admitted. DG2 PL1 intervals share its bounded power request
slot, revalidate units, preserve unrelated fields and require exact whole-
register readback. Shared BMG PCODE transactions rotate fairly at completion;
new PL1 work cannot starve an already queued I1 request. Ambiguous port loss
closes both actors, and close/reset never replays pending writes. DG2 I1 is
explicitly unsupported by the source and receives no such commands.

Protected GuC LFD1.0 export uses the existing immutable raw capture and permit
pool. It validates copied state/LIC framing and orders bounded event/crash
payloads for source-format tooling; NARF OS identity and a host comment describe
passive capture. It retains no live BO and performs no cursor/verbosity/flush
writes. Changed or malformed framing refuses before output while the raw file
remains available. This is not lossless or atomic streaming.

Source review makes four prerequisites explicit: parallel queues need a
multi-lane owner with contiguous GuC IDs, protected parent/child WQ scratch,
tail publication/enable/schedule handshakes and all-lane fences/retirement;
Gen12 direct presentation needs a production inherited-GT retirement/arena
owner; hardware cursors need owned DBUF/watermarks/SAGV policy; lifting BMG's
2133 MHz MERT cap needs coordinated actual-frequency, host L2-flush and unload
transitions. Those gates remain intact rather than being advertised by a codec.

The seventh parallel checkpoint adds four production profiles against the
same pinned Linux reference:

- Native Xe width-two, single-row COPY/COMPUTE groups use adjacent published
  dense logical instances, including sparse physical CCS pairs and BMG
  COPY0/1 on BCS0/8. Separate lane images/rings and protected scratch hold the
  real multi-LRC register/workqueue/dispatch protocol. Both lane breadcrumbs,
  saved heads, group deregistration and final TLB proof precede successful
  syncobj completion, state capture or reclamation. Child-ID replies resolve
  the group; timeout/reset lane observations remain independent. The global
  stall fallback considers progress on every unfinished lane's engines and
  excludes completed lanes. Workqueue head publication is diagnostic, so a
  delayed head and SUSPENDED status do
  not invent a protocol failure. Wider/multi-row/render groups and parallel
  GPU user-fence stores remain refused. Production coherent CPU polling uses
  an ordering fence; noncoherent cache maintenance and allocator fault/refusal
  hooks remain intact.
- Qualified MTL/Arrow VESA full-AUX SDR backlight now has a production probe,
  actual live-route/capability/D0 ownership, retained mode/waveform/caps,
  arbitrated writes and exact readback. Initial firmware mode must already be
  DPCD and the PPS gate open; disabled control keeps effective intent zero
  despite stale stored brightness. Shared AUX exclusion does not mask IRQs.
  Latest intent survives bounded Deferred retries and parking. Async T9 gate
  closure and explicitly admitted T8 relight protect suspend, failed/cancelled
  modesets, stale waiters and rollback without executor `block_on`.
- BMG adds package PL2 `power2_cap` and PL1/PL2 interval controls through the
  existing paired PCODE actor. One request slot, independent retained ceilings,
  fresh selected-field RMW, qualified sibling bounds and exact whole-pair
  source0 readback prevent accidental policy import. Close discards requests
  without replay; shared I1 fairness and passive sampling bounds remain.
- Opt-in automatic GuC failure bundles preallocate bounded immutable
  destinations before GT polling and copy the first report/log/CT under the
  retained reset owner before full teardown. Coherence/current access proofs,
  sticky loss and fixed host bounds protect copying; CAP_SYSLOG gates every
  descriptor read. CAP_SYS_ADMIN additionally permits generation-matched
  acknowledgement, with two-buffer accounting across retained old readers.
  The custom format is a partial coredump: VM/user BO/LRC bodies and lossless
  streaming remain open.

The eighth parallel checkpoint adds four bounded production paths against the
same pinned Linux reference:

- Native Xe single-row parallel groups now admit widths two through four when
  enough adjacent dense logical COPY/COMPUTE engines exist. Every lane has
  separate persistent state, runtime/watchdog observations and retirement;
  partial allocation preserves the queue and contiguous ID leases. Multi-row,
  render and GPU user-fence-join groups remain refused.
- DG2 visible VRAM uses stable tile/flat-CCS/GSM discovery, 64 KiB allocation
  and grouped PS64 PPGTT leaves. Each private allocation/reuse runs actual BCS0
  data-zero and flat-CCS clear commands before a handle, mmap or VM can expose
  it. Cancellation retains in-flight residency through retirement/reset.
  BMG allocation now reserves without BAR I/O, then clears under fresh per-chunk
  GT/D0/wake/capability ownership, retaining PM and private storage while yielding
  the GT mutex. An old clear cannot close a newer recovered epoch. Changed or
  missing layout blocks the entire recovered epoch, including old BOs. S3
  refuses live VRAM until data/CCS preservation or migration is owned.
- Qualified display14.00 MTL/Arrow Pipe-A legacy CURSOR/CURSOR2 supports linear
  64x64 ARGB with two private permanent slots. Owned pipe-off setup establishes
  and verifies PM_DEMAND, four-slice DBUF, joined MBUS, IPC and primary/cursor
  DDB/watermark resources; runtime rejects foreign pipes or changed timing.
  Writer waits, private copy and DSB arms share the KMS FIFO. Fresh terminal,
  vblank and cursor-live witnesses precede publication/reuse; close, S3 and
  reset independently stop cursor and DSB fetch before console handback.
- `/dev/dri/guc-log-streamN`, independently enabled by
  `narf.intel.guc_stream=1`, requires current CAP_SYSLOG and CAP_SYS_ADMIN.
  Two bounded host frames copy checked event/crash samples before source
  cursors and flush ACK. Backpressure withholds consumption; observed overflow,
  mutation, timeout or access loss yields an explicit error after committed
  frames. Close restores nonverbose policy with an acknowledged control;
  ambiguous restoration retains the owner until reset. The finite source's
  four-bit overflow counter prevents unconditional losslessness claims.

The ninth parallel checkpoint adds four bounded production features against
the same pinned Linux reference:

- Single-row native Xe parallel COPY/COMPUTE groups now support one GPU user
  fence. The parent waits on every child's protected payload breadcrumb,
  performs one PPGTT qword store and flushes a distinct private final marker.
  Every lane and the final join retain independent progress/timeout evidence;
  the final marker, saved heads and existing deregistration/TLB proofs precede
  successful completion or reclamation. Multi-placement, multi-row and render
  groups remain open.
- Qualified MTL/Arrow Pipe-A legacy GAMMA_GET/GAMMA_SET uses actual 256-entry
  8-bit palette mode, alongside native 1024-entry precision LUTs. Ramps are
  copied once, CTM is reset and the existing KMS FIFO/DSB owner confirms the
  hardware latch before updating the legacy store. Duplicate posted entry
  writes follow the source anti-collision sequence. Cancellation/failure,
  native roundtrips and original-palette restoration retain confirmed state;
  a missing async display owner cannot produce software-only SET success.
- BMG whole-card PSYS exposes PL1/PL2 and their intervals through the retained
  paired PCODE actor. Card, package and I1 clients share fair transaction
  ownership. Independent first-firmware ceilings, fresh selected-field RMW,
  qualified sibling limits and exact source0 pair readback protect policy.
  Optional unsupported discovery preserves unrelated clients; authority or
  ambiguous mailbox loss invalidates cached state. Close/reset drops requests
  and source ownership without policy replay.
- Default-off `narf.intel.eu_stall=1` prepares real coherent physical-DSS
  sampling buffers on BMG before startup GGTT acknowledgements and execution
  epoch publication. Current perf/admin authority gates Xe observation open,
  read and control. A bounded host FIFO copies opaque 64-byte records before
  source acknowledgement, with backpressure and explicit observed-loss errors.
  Checked MCR steering, malformed occupancy refusal and sticky access loss
  preserve ownership. Disable/reopen retains the original mapping. Active or
  poisoned collection blocks idle; busy/lost MCR escalates to full GT reset,
  and only proven GuC/DMA/full-engine reset releases exposed sampler storage.
  WAIT_NUM_REPORTS=1 is the supported bounded profile; OA and broader sampling
  profiles remain open.

The next branch starts at merged main #1308 and adds four production paths:

- Native Xe parallel COPY/COMPUTE queues accept distinct placement rows with
  immutable per-lane masks and physical restore receipts. Qualified compute
  sets permit 2×2, 2×3 and 3×2 matrices; every lane retains independent migration,
  runtime, progress and final-capture evidence. The parent mask/shift protocol,
  GPU user-fence join, saved state and all-lane DMA lifetime remain owned.
  Single-RCS and two-COPY physical limits are truthful refusals. GuC CGP
  multi-queue groups and dynamic group priority remain separate software work.
- Fixed MTL/Arrow Pipe-A admits a 129-entry equal-channel, nondecreasing
  DEGAMMA_LUT. Exact 24-bit conversion plus two extended 1.0 entries drives the
  real 131-word pre-CSC palette. Triple-blob FIFO projection, DSB pre-before-post
  programming, unchanged-stage preservation and later-frame original-state
  restoration cover joint primary/CTM/gamma changes, cancellation and recovery.
  Legacy gamma resets pre-CSC and CTM through the same owned transaction.
- EU-stall WAIT_NUM_REPORTS supports the complete physical 1..8192-per-DSS range
  with fallible preallocation up to 16 MiB of host FIFO before attachment.
  Each 5 ms sample latches readiness from host plus unread-source records, counted
  once. Nonblocking reads bypass the threshold; blocking reads require the
  sampled latch, and every successful read clears it. The defaulted filesystem
  read-options adapter carries current shared open-description status through
  scalar/vector/positioned reads and TTY forwarding. Dup/F_SETFL changes are
  sampled at invocation; blocking readv retains readiness parking.
- Version-two failure bundles retain bounded LRC, ring and parent-only group
  scratch copies under the actual reset owner. Eight fixed slots have exact
  host-owned extents, host-only lane identity, missing/truncated-data flags and
  sticky per-chunk access loss. Capture does not allocate, issue commands or
  release original storage. Privileged immutable readers remain independent of
  later mutation, reset and generation-matched clear. The sanitized public
  report still excludes raw execution data; VM/user-BO capture remains open.

The next four-feature checkpoint on `codex/intel-software-next` adds these
production paths against the same pinned Linux source:

- Native Xe HIGH priority requires current initial-namespace CAP_SYS_NICE at
  extension parsing and immediately before queue publication. CONFIG reports
  the current caller's maximum only for a valid payload request. A created
  queue retains its immutable creator-authorized GuC priority through physical,
  virtual and parallel execution. Failed authority or copyout consumes no queue
  name. Kernel-only priority remains inaccessible.
- Version-three failure bundles append four bounded resident-job VM records.
  Only allocator-owned page-table frames and submitted DUMPABLE ranges select
  sources. Each job has sixteen table pages and eight 16 KiB BO-prefix slots;
  explicit flags distinguish omitted, shortened, refused and unavailable data.
  Coherent system/WC objects and retained USERPTR pins permit passive copies
  through unfinished reservations. VRAM payload remains unavailable without a
  separate BAR-access proof. Capture changes no fence or retirement ownership;
  current raw-data authority, sticky access loss and immutable readers remain
  enforced.
- Qualified display 14.00 MTL/Arrow internal Pipe-A accepts fixed-geometry
  X-tiled XR24 WC system framebuffers. Modifier discovery follows the installed
  per-card profile. Owned disabled-pipeline setup and live readback prove
  NO-DPT/resources; padded tile extents bound both BO and GGTT windows. X/linear
  layout changes use the common DSB FIFO and independent DSB/primary latch
  witnesses. Cancellation, close, reset and master handoff retain both layouts
  until verified exact original-linear console restoration.
- Physical main-GT BMG graphics 20.01 completes actual-frequency, MCR host-L2
  setup and fresh GLOBAL_INVAL proofs before removing its 2133 MHz bootstrap
  cap through acknowledged SLPC. CPU-VRAM clears retain their target and PM
  ownership before the first BAR write; cancellation abandons the waiter while
  the GT drains its own fresh invalidation. Execution reset alone cannot retire
  pending clear targets. Post-reset manual cap, actual-frequency, flush and
  host-L2 disable proofs precede final release; failed proof retains ownership.

Pinned Linux's current DG2/BMG/MTL platform descriptors all have zero
`multi_queue_engine_class_mask`. Generic CGP firmware messages do not qualify
those platforms. Additional queue protocols therefore remain an independent
platform/firmware workstream rather than an advertised capability.

The next checkpoint adds these production paths from the same pinned Linux
source:

- Tiger Lake and Alder/Raptor Lake P/S/N have exact firmware-family selection,
  optional rather than fabricated HWCONFIG, pre-GMD topology/cache/frequency
  setup and private RCS0/BCS0 execution. All table and data addresses obey the
  39-bit DMA limit. Gen12 restore workarounds live in each owned ring and are
  repatched after saved-state restoration. MSI uses the non-tile master;
  whole reset first stops present engines and settles media power requests
  under retained forcewake. Boot-lifetime PCI/BAR claims exclude legacy engine
  attachment even after a failed or lost GuC startup.
- Fixed internal Gen12 Pipe-A linear XR24 flips preserve the driver-established
  route, bandwidth, resource and original-console mapping image. Actual native
  latch evidence retires old fetches. Changed resources, foreign consumers,
  cancellation, close and reset retain owners until exact console restoration.
  Cursor and color features require their own platform qualification.
- MTL/Arrow fixed primaries accept integer X-tiled panning and plain Tile4
  layouts. Source tiled-watermark equations feed retained original, current
  and pending images; common DSB programming and independent primary/DSB
  evidence precede release. Partial programming failures and reset preserve
  the watermark journal and every potentially fetched allocation.
- Trusted DG2/BMG range copies use private BCS0 address spaces, atomic BO
  reservations and retained PM/table/data ownership through terminal completion
  or proven reset. BMG supports local upload/copy/readback; DG2 preserves local
  flat-CCS ownership and refuses unsupported compressed system representations.
  This primitive does not revoke CPU aliases or implement eviction/migration.
- PCI runtime-power policy exposes bounded current-admin/epoch requests for
  force-on, eligible autosuspend and signed delay. Accepted requests report
  their applied/error outcome separately. Cached enabled-PM accounting never
  wakes the GPU; stale samples cannot recount time. Disable abandons canceled
  callbacks without inventing a successful hardware transition.
- Every supported engine's isolated-reset ADS set includes its applied source
  workarounds, tunings, command-cache policy and all installed nonprivileged
  register slots, using immutable qualified MCR steering. Register lists are
  bounded before ADS publication. Independent native fixtures erase and replay
  engine state through the actual ADS/CT conversation before new private work.

The next checkpoint extends the source-qualified Gen12 fixed internal display
without broadening timing, output or plane admission:

- CTM has its own capability and retained route/resource/console-PTE owner,
  including color-only sessions and partial-arm/reset recovery.
- A stopped-pipe PCODE-qualified S1/S2 DDB/watermark partition reserves a fixed
  64x64 cursor. Private PAT-free DMA39 slots and generation-specific DSB status
  require independent command, cursor and later-frame evidence before reuse.
  Cursor fault bit11 is checked on Gen12 and the existing MTL path.
- Native gamma/degamma sizes follow display12 (262145/33) and display13
  (1024/129); both support legacy256 gamma. Gen12 pre data uses Q16 and MTL
  retains Q24. Large display12 blobs have an exact 2,097,160-byte ABI bound,
  with separate 16 MiB stored-payload and concurrent-copy budgets per Card.
  Display12 fine/coarse post-LUT RAM has no reliable source readout: complete
  canonical DSB writes, independent retirement, a later frame and readable
  endpoints/controls prove its qualified owned pipeline. Clear/reset restores
  the original visible bypass; inactive RAM remains exclusively owned and is
  completely rewritten before new activation. Display13/MTL preserve their
  stronger indexed readback/restoration. Joint Gen12 primary/color remains
  unadvertised pending its separate qualification.
- GuC NARFGSTR v2 shares one flush/ACK actor among four retained descriptions,
  each with two fixed FIFO slots. A staging buffer and transactional fanout
  spare bound total storage to 821,760 bytes per card. Whole unread records
  may be replaced; partial records stay immutable. Host dropped-frame/wire-byte
  accounting is exact until explicit saturation; firmware's four-bit overflow
  counter yields observed lower bounds only. Actual firmware incarnation and
  a nonreused publication serial prevent queued-open replay across park,
  reset, reupload or republication. All descriptor operations use host copies
  and current admin/syslog authority. Admission follows the exact typed GuC 70
  profile and per-family minimum version, covering Gen12, DG1, DG2/ATS-M,
  MTL/ARL, BMG, LNL, PTL/WCL and NVL-S without architecture aliases.
- The legacy Gen12 GGTT arena and PPGTT-root attachment enforce DMA39 before
  mapping/image writes; qualified DG2 arenas keep DMA46.

The following integration batch carries required source corrections for
ADLP/N primary alignment/arbitration slots, Gen12 console-layout restoration
and common Gen12 nonrender LRC workarounds. These corrections are included in the following native checkpoint;
the remaining features continue on this branch.

The next integration batch extends the same pinned source contract:

- Fixed Gen12 primary/color DSB commits now share native-frame publication.
  X tiling and integer panning keep timing/bandwidth unchanged. Required
  ADLP/N 16 KiB SURF alignment and ARB_SLOTS=1 apply to every linear/X direct
  and joint path. Exact original-family CTL/stride restores the console.
  External DP/HDMI/MST/USB-C metadata now carries the exact PCI family;
  missing/foreign metadata refuses before side effects and retains the session.
- LNL 20.04 and PTL 30.00/30.01 main-GT execution uses exact PCI/firmware
  profiles, five-level private address spaces and source cache/context/ADS
  policies. Serial/headless startup permanently excludes boot publication
  before an acknowledged whole-display driver reset. The retained media
  proof covers all arena writes/invalidation and source 63-PTE ordering;
  four raw zero writes precede every GPU MMIO read. Graphical boot, display,
  HuC and separate media-GT execution stay unavailable on these profiles.
  PTL preserves all 96 physical DSS positions and acknowledged DCC policy.
- Fuse-present Gen12 VCS/VECS execute through the existing main GuC, using
  source video AUX/MI_FLUSH commands, hardware-captured defaults, bank 1 IRQ
  and the same retained media wake owner through scheduling/reset. Common
  Gen12 nonrender LRC WAs also correct the existing BCS default path. Media
  ADS/KLV extents validate before mutation. Native Xe and legacy i915 queue
  selection use the real published engines and existing private-VM lifetimes.
- Intel CPU mapping tokens and a whole-BO physical census preserve the same
  object through pending publication, PROT_NONE/lazy and unpublished-fork
  metadata, even after handles/tokens/PRIME close. The bounded permanent
  registry preserves AMD aliases. This is a lifetime prerequisite; immutable
  BO storage, eviction, PREFETCH and asynchronous CPU revocation are unchanged.

The remaining broad workstreams still need production ownership/protocols.
Two source limits are not missing features of the admitted set: its pinned
platform descriptors expose no CGP class mask, and Xe hwmon fan/temperature
attributes are read-only (power/current are the writable controls). The next
slices now include the low-latency queue policy and exact LNL sampler below;
retained placement transitions, separate media GTs and MMU invalidation remain.

The follow-on retained external-display patch is correcting exact-family
plane inventory in stopped-resource and GT-bootstrap reads, with independent
absent-register refusal fixtures. Its source review and validation remain
separate from this native checkpoint.

The next two-feature slice implements immutable native Xe low-latency hints
and exact LNL EU-stall observation. CONFIG reports the hint only for a live
matching nonzero epoch/platform, nonempty engine publication and submission
ABI1. The boot owner independently enforces CSS minima. Real hardware queues
retain the hint through source key0x2005/value bit28 before ENABLE; ordinary
queues explicitly send zero. Global acknowledged SLPC limits remain owned by
the existing actor. Source fast-policy enqueue has no separate ACK and never
establishes job completion. Queue cancellation, lost acknowledgements and
close retain all reachable lane/VM/BO state until terminal retirement/reset.

The default-off LNL sampler reuses the existing owner and startup arena. It
verifies exact GAM MOCS3/PAT2, current media/cache/MMIO authority and physical
DSS positions before publishing data. It retains uncertain DMA through the
same independent reset and arena-before-media-release protocol. PTL sampling,
codecs, HuC on these LNL/PTL profiles, separate media GTs and physical
Intel/Mesa acceptance remain separate. Exact TGL has the distinct opt-in below.

### Retained external SST, i915 ASYNC and exact-TGL HuC checkpoint

Three bounded production slices extend the validated v0.33 checkpoint.
The ledger contains 61 implemented checkpoint rows and ten broad open
workstreams. Debug and release native model validation passes; source review
and native models do not establish physical Intel or Mesa acceptance.

- Retained external display owns one source-qualified Gen12 combo-B SST stop
  graph. Current capability/D0 and observed PCH identity gate masked SDE/SHOT
  polling; fresh initialization prevents inherited LONG from converting a
  short pulse into unplug. Independent plane/pipe/DDI stop witnesses precede
  serial-matched withdrawal. PM/reset uses the same state outside the GT mutex;
  cancel/lost authority/failed status retains the graph and stopped/quarantined
  storage remains reserved. HDMI/MST drain, reconnect/retrain, resource
  repartition and broader outputs remain separate. Exact TGL7/ADL5 and DG2/BMG5
  plane inventories correct absent-register probes in existing admission.
- I915 EXEC_OBJECT_ASYNC bit6 is bounded to current BMG ordinary system WB
  softpin objects, including same-card WB PRIME. GETPARAM43 reflects only live
  matching admission. Flagged entries skip prior implicit GPU dependencies;
  unflagged entries, explicit inputs and same-context order remain mandatory.
  Alias folding and mixed final admission stay atomic under the common gate;
  every BO keeps its terminal READ/WRITE fence and CPU-copy/PRIME exclusion.
  Cancellation, close, cache uncertainty and missing retirement retain state
  until terminal completion or proven reset. Local/WC/VM-owned/pinned-user
  objects and other platforms refuse. CPU mmap stores remain client ordered;
  arbitrary stores are not frozen or revoked. Native Xe ordering is unchanged.
- Default-off narf.intel.huc=1 applies only to exact physical Tiger Lake.
  Authorized canonical i915/tgl_huc.bin acquisition precedes WOPCM planning;
  the real BO/upload/RSA extent survives both HuC-before-GuC DMA passes and
  reload. Confirmed PC/SLPC Running, typed AUTHENTICATE_HUC with DATA0=0 and a
  fresh independent c1dc success bit establish readiness. The sole CT owner
  routes disjoint fences4000..7eff alongside context/log/SLPC traffic. BUSY/
  RETRY preserve one conservative total1s request bound; status has100ms.
  Xe query7/type1 returns the running CSS release under current reset/D0/wake
  authority or ENODEV, without loading/authenticating/waking/resuming. Type0
  keeps its GuC compatibility ABI. Sticky DMA exposure survives failed reload;
  lower BootStaged/Stopped cannot free it before upper full Gen12 reset/media
  retirement. TGL autosuspend remains refused. ADL, MTL/Arrow, DG2/BMG and
  headless LNL/PTL gain no HuC profile; their existing defaults/owners remain.
  I915 GETPARAM42, codecs, media-GT, GSC/PXP/protected content remain separate.

The HuC fixtures do not execute the positive Firmware::open/registry/
stage_with_huc acquisition chain or actual RuntimeOwner/PCI/system-PM
coordinator callbacks. The firmware-reset portion exercises full stop and
fresh GuCGt owners; a separate fixture uses real GGTT/cache allocation and
staged cleanup. Production acquisition/PM wiring is manually reviewed only.
Native register/CT/ownership models do not execute Intel firmware or prove
physical Intel, S3, Mesa interoperability or codec acceptance.

Primary source remains Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
i915_drm.h, i915_gem_execbuffer.c, i915_vma.c and i915_getparam.c for ASYNC;
xe_pat.c for BMG PAT2; xe_uc.c, xe_huc.c, xe_guc.c, xe_uc_fw.c, xe_wopcm.c,
xe_guc_ct.c, xe_query.c and the corresponding HuC/GuC register/action headers
for the exact TGL transaction. Public contracts are in spec.md §3.

### i915 context frequency and media SSEU checkpoint

This batch adds one bounded context-frequency checkpoint and extends the
existing legacy media query contract. The ledger contains 62 implemented
checkpoint rows, with ten broad workstreams open.

HAS_CONTEXT_FREQ_HINT59 passively writes 1 only for current qualified GuC ABI1
admission; unsupported state writes signed -22 while the ioctl succeeds.
LOW_LATENCY0xe enables by presence, including value0 and nonzero size, through
CREATE_EXT on admitted profiles or an unfinalized major12 proto-context SET.
BMG/LNL/PTL require the create extension. All real RCS/BCS, indexed physical/
virtual and lazy Gen12 media contexts preserve intent through the existing
policy KLV before ENABLE; ordinary contexts send zero. Global SLPC and the
existing cache/retirement/reset lifetimes remain unchanged. CREATE now reserves
a private nonce-bound name, configures copied state and selected VM references
off-lock, performs faultable copyout without the namespace IRQ lock, and only
then publishes by identity. Pending lookup/mutation/destroy/EXEC return ENOENT;
rollback cannot remove an interleaved creator or drop private graphs under the
namespace guard. Pending reservations count against the existing limit.

Nonindexed Gen12 media GET_SSEU uses actual published dense logical engines and
immutable whole-device defaults. A host-only per-context observed inventory
survives stop without granting execution; never-observed unavailable media
returns ENODEV and known absent logical engines return EINVAL. Existing indexed
holes/ignored-class, size/fault/finalization, eight-bit and PTL limits remain.
A public witness context checks exact retained VM identity after original VM
name deletion and replacement during reentrant context copyout.

### BMG GPU-only VRAM, i915 capture and reset availability checkpoint

This batch adds three bounded checkpoints. The ledger contains 65 implemented
checkpoint rows, and all ten broad workstreams
remain open. The local-memory and diagnostics backlog rows describe the remaining
scope; neither broad workstream is closed by these exceptions.

- Exact physical BMG graphics20.01/20.02 gains default-off pre-`--`
  `narf.intel.bmg_smallbar=1`, permanently headless/client-free fresh driver-FLR
  takeover and separate visible/GPU-only pools excluding DSM/GSM/flat-CCS tails.
  Born GPU-only backing never acquires a CPU alias. Actual trusted COPY0 zero
  initialization must retire successfully before a handle. Private WB staging,
  high-DPA/PTE/cache/MERT proofs, retained preterminal count/bytes and off-lock
  reentrant copyout followed by current owner/exact-VM/token publication retain
  cancellation/lost-ACK/reset ownership. CPU/mmap/diagnostic/user-fence/PRIME/
  KMS/i915/ASYNC paths refuse this storage. Ordinary GT reset never repeats the
  destructive FLR; opted-in runtime/system PM initially refuses. Default BMG
  and other profiles retain their prior behavior. The existing HuC option also
  follows the corrected pre-separator boot grammar.
- I915 object bit7 retains actual selected WB/same-card-import mappings and
  bounded safe payload prefixes in the existing immutable native-v3 dump.
  Cached GETPARAM45 follows live matching ABI1 admission. Context parameter4
  accepts size0/any-nonzero SET even after finalization; one source-live policy
  spans all engine/map/virtual/lazy-media members and retained jobs after close.
  Any protected retained i915 context suppresses the entire new raw bundle
  before backing reads, a deliberate NARF whole-bundle choice. Normal UserJob
  saved-state/terminal processing, old immutable readers, capabilities, boot
  opt-in and diagnostic bounds remain. Full Linux dump/sysfs/batch parity and
  additional storage rights remain outside this subset.
- Cached GETPARAM35 reports automatic whole-GT reset level1 only with current
  user admission and a distinct worker/incarnation-bound sealed every-engine
  execution/terminal qualification witness. Refusal defaults0. Faults and
  accepted transitions withdraw it; a refused transition which leaves Running
  intact preserves it. Proved stop precedes permitted Cold recovery; clean park
  requalifies before adopting its prior user epoch. Cancellation retains uncertain
  DMA while closing admission. No per-engine level2/value3, manual reset, replay
  or broader recovery/PM authority is added.

The BO fixtures drive actual raw Xe/GT/CT/LRC/PPGTT, cache/MERT, copy, terminal
and reset ownership; their publication transport substitutes for the physical
RuntimeOwner PM/reset mutex. Three physical-path fixtures exercise actual
retained capability/PCI/BAR AuthorizedWindow, driver-FLR/media conversation and
cache-to-first-PTE code using owned fake config/MMIO RAM. Capture fixtures use
actual raw i915 selection, retained job payload, live policy and descriptor
capability paths. Reset fixtures exercise the common recovery coordinator with
real GT execution models. These are not positive full RuntimeOwner/firmware
registry/physical PCI power callbacks or S3 executions. Physical Intel, Mesa,
codec and performance acceptance remain unrun. No silicon or full physical
owner result is claimed; OA and all ten broad workstreams remain open.

### MTL legacy modeset failure correction — software gates recorded

This corrects false success in the existing MTL/Arrow legacy modeset path; it
adds no feature row. The ledger remains at 65 rows with all ten broad workstreams
open. Local stop/clock/current and final source/primary/fresh-frame failures now
abort later programming. The inherited clock fast path uses the actual locked
clock and programmed squash window; an unmet floor refuses. Already-on DDI
ownership is required, and unqualified direct TC1/TC2 routes refuse before MMIO.
No DDI-off initialization, new await, resource allocator, retirement receipt or
scanout reclamation is added. Pre-stop fixed GGTT/cache/bootstrap, full source/
sink training, inherited producer exclusion and general resource/clock ownership
remain software work.

Four fixtures are added. The existing misleading
`smoke_mtl_modeset_tc1_full_run` is replaced, with no count increase, by
`smoke_mtl_modeset_tc_ports_refuse_unqualified_route`. Expected inventories are
1,912 selected tests (1,242 Intel/DRM/fb/backlight plus 670 shared), including all
1,907 unchanged NEXT9 names and this exact replacement. The original baseline
retains 1,086 names unchanged plus the replacement. All prior 152 cumulative new
labels remain; four additions and one replacement make 157 new-or-replacement
labels, not five added tests. Group 3 grows to 189; group 5 stays at 197.

The fixtures use actual dispatch and an actual scheduler task over modeled
hardware. Full physical RuntimeOwner, positive firmware registry, PCI power
callbacks, S3 and controller/console publication remain manually traced rather
than executed by these new fixtures. Silicon, visible-pixel, complete-link,
Mesa, codec and performance acceptance remain unrun. No broad workstream closes.

### Fixed opaque XR30 input — software gates recorded

The bounded opaque XR30 slice adds LINEAR four-byte XRGB2101010 input to the existing exact fixed MTL/Arrow internal profile, with integer panning, real projected FIFO state and retained joint primary/color restoration. Current backend epoch publication and explicit reconciliation preserve owner authority. Output depth/HDR, other formats/platforms, global bandwidth policy and broader display work remain outside this slice. The ten broad workstreams remain Open.

The expected selection is 1,918 tests: 1,248 Intel/DRM/framebuffer/backlight plus 670 shared. All 1,912 NEXT10 names remain unchanged; six new registrations bring the cumulative new-or-replacement labels from 157 to 163. All 31 backlight regressions remain. The six additions belong to the existing intel_gpu_dsb namespace in group0 (369); group4 remains135 and group5 remains197.

The new fixtures exercise shared GETPLANE/IN_FORMATS/GET_CAP query helpers,
real Card::addfb2_intel and raw atomic/PAGE_FLIP/DIRTYFB/cursor/master FIFO
conversations through actual Device/Guard/Presenter/PollIo/color/DSB owners and
PTE-decoded command backing. They do not execute the full DriCardFile/registry
user-copy GETPLANE/ADDFB entry or physical backend-publication refresh. Their
held-Device Pending seam exercises the shared owner directly; it does not
execute the physical scanout_access drain. Actual RuntimeOwner/ECAM, positive
firmware registry, physical startup/full system-PM coordinator, sink training,
visible pixels, Mesa/codec and performance acceptance remain unexecuted by these
fixtures. Supported WC backing is required for positive DMA conversations;
unsupported architectures retain conservative source/metadata/WB refusal.
Native register/CT models are not physical Intel or ARM-native acceptance.

### MTL/Arrow standalone media GT lifecycle checkpoint — release gates recorded

Meteor Lake and Arrow Lake carry Xe_LPM+ (media IP 13.00) as a separate GT1
behind the media GSI window. `intel_gpu_media_gt` (mounted as
`intel_gpu_gt::media`) adds an exclusive per-incarnation owner that applies
Linux xe's media GT register definitions for that one profile. Register offsets below
0x40000 translate by 0x380000 (`xe_mmio_adjusted_addr`); media engine bases
and GSC HECI registers stay absolute. Admission requires an MTL-classified
device whose published GT0 graphics IP is 12.70, 12.71 or 12.74 and two equal
media GMD_ID samples reporting 13.00. Version 0 is reported as an absent
(fused-off) media GT and any other version as unsupported; neither writes a
register. The owner then takes the media GT forcewake domain
(FORCEWAKE_GT/FORCEWAKE_ACK_GT_MTL), re-reads GMD_ID under wake, derives the
present VCS0-7/VECS0-3 set from GT_VEBOX_VDBOX_DISABLE with positive polarity
(GSCCS0 stays absent without loaded GSC firmware). With every present
VDBOX/VEBOX domain awake it programs the xelpg PAT through the media steering
semaphore and multicast selector, media 13.00 GT workarounds 22016670082 and
per-VDBOX 16021867713, and the shared `mtl_mocs_desc` global/LNCF tables. It
then resets only the media GuC with a GS_MIA_IN_RESET proof, releases every wake
request it made and reports the identity, fuse word and engine set.

Reset policy (since the default-off gate below): probe performs no GT reset,
as Linux media-GT probe does (`xe_uc_sanitize_reset` after PAT, workaround and
MOCS setup). The full GRDOM_FULL reset bracketed by Wa_14015076503 runs only in
the recovery owner (`MediaGt::for_recovery`), once per GT0 incarnation after a
faulted media GuC has proven its stop. This mirrors `gt_reset_worker`, which
runs `do_gt_reset` and then `do_gt_restart`. The whole path stays off unless
`narf.intel.media_gt=1` is given.

Inherited media wake requests or an in-flight GDRST refuse as busy; stale sleep
acknowledgements from an earlier incarnation are settled within the source's
50 ms bound before a new request. Wake, reset and semaphore bounds, unstable
identity, empty inventory, lost wake and lost access are typed refusals. Each
releases the owner's own wake requests and clears a pending GSC notification.
The steering semaphore is never held across a return. NARF refuses a semaphore
that is not granted, where Linux warns and proceeds. No path writes a GT0
register.

The GT runtime starts one owner after an MTL-classified GT0 incarnation reaches
Running, polls it from the per-card worker with current D0 checked before each
step, and logs the outcome once. A refusal ends only that media attempt and is
never a GT0 error. GT0 fault cleanup, runtime park, system-suspend preparation
and every other non-Running phase first abandon the owner, synchronously
releasing its outstanding wake requests. The next GT0 incarnation starts a fresh
owner. No GT1, media engine, interrupt source, firmware version or HuC is
published: the GT list and engine queries stay GT0-only, and exec-queue
creation still refuses non-GT0 placements.

Twelve native fixtures register under `intel_gpu_media_gt`. Eleven
register-model cases cover the positive sequence, pre-write refusals,
wake/reset/semaphore timeouts, GSC workaround ordering, current loss and
teardown with next-incarnation settling. Each asserts that GT0 registers are
untouched. One native Xe conversation on the MTL GuC model shows that the GT
list and engine query stay GT0-only. It also shows that VCS/VECS or gt_id 1
placements return EINVAL before any allocation.

#### Media GuC, CT and shared-GGTT invalidation

The media GuC now runs through the existing GuC owners. They take a
Primary/Media role instead of being copied. `GuCBoot::stage_media` and
`GuCGt::stage_media` accept only an owned `MediaGsi` window. The media role
therefore always pairs GSI-translated GuC reset, WOPCM, DMA, status, parameter
and TLB registers with the absolute media mailbox (MED_VF_SW_FLAG(0..3) and
MED_GUC_HOST_INTERRUPT). GT0 keeps VF_SW_FLAG/GUC_HOST_INTERRUPT unchanged.
The media GuC boots GT0's MTL GuC image (xe_uc_fw.c GT_TYPE_ANY) with the same
WOPCM plan and a minimal ADS that enables no engine. Before DMA it re-verifies
the staged media GMD_ID under media wake. It never queries HWCONFIG (Linux reads
it from GT0 only) and reserves no HuC image. Its workaround profile comes from
the standalone-media RTP split: GuC flag 22 for Wa_14018913170, and ADS KLVs
0x9002 (Wa_16021333562) and 0x900b (Wa_16026508708). GT0's graphics-only
CCS/POLLCS/PRE_PARSER choices do not apply. The bare `GuCGt` path takes the
media GT forcewake domain, boots, enables CT, and proves stop with a GuC reset,
DMA idle, CT/ADS/log release and wake-release acknowledgement.

`MediaGuc` wraps that owner. It keeps the media GuC2Host half (bit 15) of
GUC_SG_INTR_MASK masked and polls its CT, as GT0 does; GT0's half and the shared
enable stay untouched. Before the media wake request, it registers the media GuC
as the shared GGTT arena's second TLB. While registered, every arena PTE
publication and clear also writes the media GUC_TLB_INV_CR (at the GSI base). This
matches xe_ggtt_invalidate on both GTs while media GuC submission is off.
Without a registered media GuC, the arena invalidates GT0's GuC only (GT0's
own invalidation is described at the end of this section). An unsolicited
G2H message on the idle media CT is a protocol failure that begins a stop. A
stop that cannot be proven leaves the owner retained, keeping its firmware memory
and the TLB registration.

The runtime starts one media GuC after the media GT lifecycle owner initializes.
Before a new GT0 arena is built (cold start), before runtime park and before
system-suspend preparation, it waits for a proven media GuC stop. Park refuses
as busy and suspend fails if that proof is missing. A retained media GuC leaves
GT0 failed instead of rebuilding the GGTT arena underneath firmware that may still
translate through it.

Four further fixtures register under `intel_gpu_media_gt`:
- Media GuC boot, CT enable and stop on the GuC model, writing only GT1
  registers.
- Staging and identity refusals that publish nothing.
- MediaGuc TLB/IRQ ordering, current-loss stop and retained unproven stop.
- The real shared arena over a RAM-backed BAR, with and without a registered
  media GuC.

They are native models, not physical Intel evidence.

#### Default-off gate and media-GT reset policy

The whole media GT path is default-off behind `narf.intel.media_gt=1`. This
covers the lifecycle owner, media GuC, CT and second-TLB registration. The
option uses the shared pre-`--` grammar now also used by `narf.intel.huc` and
`narf.intel.bmg_smallbar`, via `intel_gpu_gt::boot_opt_in`. Without the option,
the runtime constructs no media owner. Every GT0 retire, park, suspend and
cold-start hook then completes with no MMIO, and the arena never registers a
second TLB.

Reset policy follows Linux media-GT probe. Probe resets only the media GuC
(xe_uc_sanitize_reset -> xe_guc_reset: GRDOM_GUC and GS_MIA_IN_RESET), after
programming wells, PAT, workarounds and MOCS. Probe performs no GRDOM_FULL and
no GSC notification. xe_gt.c::do_gt_reset, which issues GRDOM_FULL bracketed by
Wa_14015076503, runs only from gt_reset_worker and xe_gt_shutdown. NARF applies
it only through `MediaGt::for_recovery`. After a faulted media GuC has proven
its stop, the runtime runs one such recovery owner per GT0 incarnation and then
restarts the media GuC, mirroring gt_reset_worker's do_gt_reset followed by
do_gt_restart. Driver shutdown is not modelled.

One new fixture registers under `intel_gpu_media_gt`:
`smoke_media_gt_default_off_gate_and_absent_option_leave_gt0_unchanged`. It
covers the grammar and its parity with the HuC and small-BAR options, platform
admission, the MMIO-free retire hook, and an unregistered real arena. The probe,
reset-failure and GSC fixtures now pin the corrected probe and recovery
sequences.

With the option absent, the runtime builds no media owner, `media::retire`
returns `Done` without MMIO, GT0 install, park, suspend and cold-start proceed
as before, and the arena registers no second TLB.

#### Media engines, interrupts and native Xe gt_id 1

The media GuC now schedules GT1's fused VCS/VECS engines through the shared
GuCBoot, GuCGt and GuCScheduler owners. Linux reads HWCONFIG on GT0 only, so
the media role builds its engine list from the media fuses and its ADS from
that list: logical-to-physical maps, enable masks, golden LRCs and per-engine
register saves. GT1 has no render reset domain, so the ADS saves no RCU or CCS
mode. While its engines are scheduled the owner holds every present VDBOX/VEBOX
wake. Every GT1 wake proof checks those wakes. The owner installs the
oam_mmio_trg_vcs/vecs NONPRIV grants with NOPID fill and enables each ring, then
reloads the GuC. No engine workaround or tuning entry matches media 13.00
VCS/VECS.

Default LRCs follow xe_gt_record_default_lrcs. On GT1 the media 13.00 WA job is
empty, because no LRC workaround or tuning rule matches a standalone media GT.
Images use dg2_xcs_offsets, as Linux keys them on the device graphics IP.
Video rings follow __emit_job_gen12_video. MTL has no flat CCS, so AUX
invalidation applies; emit_aux_table_inv adds GT1's MMIO adjustment, which
places VD0/VE0_AUX_INV at 0x384218/0x384238. Once submission is enabled, the
shared arena stops writing GT1's GUC_TLB_INV_CR. The media scheduler's CT
TLB_INVALIDATION covers GT1 instead, as send_tlb_inval_ggtt does with CT and
submission enabled. Since the shared-GGTT TLB checkpoint at the end of this
section, that is a GGTT request per update rather than the per-context one.
Stop reverts to MMIO. GT1 is declared ready only after each engine runs its own
private-PPGTT store job, retires it and verifies the result.

Stop follows GT0's verified model: GuC reset, media GRDOM_FULL with a
scheduler, DMA idle, memory release and wake release, with engine wakes
released last. NARF never loads GSC firmware and has no owner for
Wa_14015076503. Scheduling therefore refuses while GSC firmware reports loaded,
and a later load keeps the owner retained rather than resetting without the
workaround.

Published engines' user interrupts are routed onto GT0's tiled MSI. The owned
bits are the VCS/VECS halves of VCS_VECS_INTR_ENABLE, the mask-pair halves
and each RING_IMR. GT0's sources and both GuC halves are untouched. Bank-1
identities decode as VIDEO_DECODE/VIDEO_ENHANCE and only wake the worker that
polls GT1. Sources are masked again before GT1 leaves Running. Without
delivery, GT1 is serviced from the worker's timer.

With the option on, native Xe lists GT1 only after every engine's job has
verified, and only while GT0's epoch is live. The GT list then has a MEDIA
entry (gt_id 1, GT1's own clock and GMD_ID). The engine query adds VCS/VECS on
gt_id 1, and queue creation resolves placements per gt_id in
xe_exec_queue_create_ioctl's errno order. EXEC submits to the media GuC under
GT1's epoch. With the option off, or before publication, the UAPI is GT0-only
exactly as before. Silicon and Mesa acceptance remain open.

New fixtures register under `intel_gpu_media_gt`:
- `smoke_media_gt_sched_engines_prime_probe_publish_and_stop` and
  `smoke_media_gt_sched_refusals_stop_and_publish_nothing` run the GuC model
  through scheduling, priming, probes, a user job and verified stop. They also
  cover wake timeout, loaded GSC, a dropped store and owner-level refusals.
- `smoke_media_gt_video_ring_ops_and_lrc_layout` checks the ring and LRC
  layouts.
- `smoke_media_gt_shared_ggtt_ct_mode_after_submission_enable` covers the
  shared arena's invalidation modes.
- `smoke_mtl_media_gt_irq_routes_published_engines_and_restores_owned_bits`
  covers interrupt routing.
- `smoke_xe_mtl_media_gt1_published_queries_queues_and_exec` exercises the
  published UAPI. The existing unpublished conversation remains its negative
  counterpart.

The MediaGuc owner fixture was updated: a booted media GuC now takes its engine
wakes instead of enabling an idle CT. These are native models, not physical
Intel evidence.

Once media submission is on, the arena stops writing the media GUC_TLB_INV_CR.
The media scheduler's TLB_INVALIDATION (0x7000) around context registration
and deregistration then covers GT1, as GT0's scheduler does for GT0. Linux
`xe_ggtt_invalidate` instead sends one CT invalidation per GGTT update on each
GT, so this was a deliberate NARF policy. The shared-GGTT TLB checkpoint at
the end of this section replaces it with Linux's per-update invalidation on
both GTs. Media 13.00 uses AUX invalidation (MTL has no flat CCS) at the
GSI-adjusted VD0/VE0_AUX_INV (0x384218/0x384238), as `emit_aux_table_inv` adds
the media `adj_offset`. With `narf.intel.media_gt=1` absent, GT0 interrupt
routing, scheduling, the arena and the UAPI are unchanged.

#### GT1 engine cycles and topology, and the GSC/HuC formats

With GT1 published, the last two native Xe queries now cover it, following
xe_query.c. DRM_XE_DEVICE_QUERY_ENGINE_CYCLES checks size, the input copy and
the clock ID as before. gt_id 1 then resolves only while GT1 is published,
every other nonzero gt_id is EINVAL, and the class and logical instance must
exist on GT1. The media GuC samples RING_TIMESTAMP and its upper dword at the
engine's absolute base. Media engine bases lie above MEDIA_GT_GSI_LENGTH, so
xe_mmio_adjusted_addr leaves them unchanged. It uses GT0's sampler, which
rechecks GT1's GT wake and every held VDBOX/VEBOX wake in place of Linux's
XE_FORCEWAKE_ALL. The width is 36 bits. A lost GT1 wake returns EIO, unpublishes
GT1 and starts the media GuC's verified stop. Userspace converts cycles with
GT1's reference clock from the GT list.

Linux runs xe_gt_topology_init on the media GT as well. Media GT probe
therefore reads GT1's own GSI-translated geometry DSS, compute DSS and EU enable
fuses under GT wake. It takes two equal samples and keeps empty masks, since
real media GTs may have no DSS, and refuses reserved EU bits as unavailable
MMIO. DRM_XE_DEVICE_QUERY_GT_TOPOLOGY appends GT1's geometry, compute and SIMD8
EU-per-DSS entries after GT0's, in for_each_gt order. They use GT0's existing
NARF wire widths. Like GT0, GT1 reports no L3 bank entry, although Linux reports
one for pre-Xe3 media GTs. With the option off, or before publication, both
queries are byte-for-byte GT0-only.

The GSC and HuC work starts with a model-only module,
`intel_gpu_gt::media::gsc`. It covers the MTL firmware identities: the GSC
image `i915/mtl_gsc_1.bin`, matched on compatibility major 102, and the HuC
image `i915/mtl_huc_gsc.bin`, which has no version requirement. It covers
parse_gsc_layout and parse_cpd_header for the GSC image, including the RBE
partition and RBEP.man release and security version. For the HuC it covers
parse_headers, where the CSS sw_version overrides the HUCP.man release,
together with the DMA window and RSA offset. It also covers the GSC HECI header,
reply and pending-handle rules, the GSC_HECI_CMD_PKT and GSC_FW_LOAD batches,
the MKHI compatibility query and the PXP 4.3 NEW_HUC_AUTH packet. Each refusal
carries the errno of its source branch.

Three source facts shape the HuC and GSC work.
- Linux sets the MTL HuC running after a DMA upload from its embedded CSS
  followed by media-GuC authentication (xe_uc_load_hw). That state is what
  query_uc_fw_version reports. GSC authentication is a second, PXP-oriented
  step.
- huc_auth_via_gsccs runs before xe_gsc_proxy_start and needs only a GSCCS
  packet to the PXP HECI client. The MEI/PXP/HDCP proxy is therefore out of
  scope for HuC.
- Linux's separate huc_firmware_path and gsc_firmware_path parameters make
  HuC and GSC independently optional.

New fixtures register under `intel_gpu_media_gt`:
- `smoke_media_gt_topology_reads_gt1_fuse_mirrors_under_gt_wake` and
  `smoke_xe_mtl_media_gt1_engine_cycles_and_topology` cover the two queries.
- `smoke_media_gsc_firmware_identities_and_compatibility_policy`,
  `smoke_media_gsc_layout_parse_and_every_refusal`,
  `smoke_media_huc_gsc_image_versions_offsets_and_refusals`,
  `smoke_media_gsc_heci_packets_follow_xe_gsc_submit` and
  `smoke_media_huc_auth_modes_read_gt1_registers` cover the formats.

#### MTL HuC on the media GuC, and GT1's L3 bank entry

The MTL/Arrow HuC is now loaded and authenticated by the media GuC, following
Linux xe without the GSC. xe_huc.c::xe_huc_init gives the HuC to the primary
GT only up to graphics 12.55 and to the media GT above it, so the existing
HuC owner (`intel_gpu_huc`) is parameterized by GuC role rather than copied:
TGL stays on GT0, and MTL/Arrow uses GT1. The MTL HuC needs both
`narf.intel.media_gt=1` and `narf.intel.huc=1`. The media GT must exist for it
to have an owner. Linux makes HuC separately optional through
huc_firmware_path, while the media GT always runs. Requiring the HuC option
therefore keeps `media_gt=1` alone exactly as before, with no WOPCM, DMA,
firmware or query change.

With both options set, the runtime acquires the authorized
`i915/mtl_huc_gsc.bin`. It parses the GSC CPD headers (or a whole-file CSS)
and stages the whole file as the HuC object, as uc_fw_copy does. The media
GuC's WOPCM reserves the CSS header plus uCode below an aligned GuC base and
sets HUC_LOADING_AGENT_GUC (xe_wopcm.c). The HuC DMA copies from the object's
GGTT base plus css_offset to WOPCM offset 0 while the GuC is held in reset.
It runs before the submission GuC load only: xe_uc_load_hw uploads the HuC,
but xe_guc_min_load_for_hwconfig, the media GuC's minimal first boot, does
not. TGL keeps its DMA before both of its loads. After the default LRCs and
the private per-engine jobs, the media CT sends AUTHENTICATE_HUC with the GGTT
base plus xe_uc_fw_rsa_offset. A zero-result reply and the success bit of
HUC_KERNEL_LOAD_INFO, read at 0x38c1dc through GT1's GSI window within
100 ms, make the HuC RUNNING. Linux starts PC before this step; NARF runs no
SLPC on GT1, so authentication follows directly.

DEVICE_QUERY query7 type1 on MTL/Arrow reports the release of the media GT's
running HuC: the CSS sw_version, not the HUCP.man version. As in
xe_query.c::query_uc_fw_version for MEDIA_VER >= 13, GT0 never answers on
these devices. The query returns ENODEV without a published GT1, before or
after authentication fails, when the status bit reads clear or lost, and under
lost access. It is passive and never loads, authenticates or wakes anything.

Every new media GuC repeats the upload, so media-GT recovery and system resume
both reload the HuC. xe_huc_auth checks the authentication bit before
requesting, and Linux reports an already-authenticated HuC as RUNNING, because
on these platforms the HuC survives GuC/GT reset. NARF adopts such a bit only
when an earlier media GuC of the same owner authenticated this image itself.
An inherited bit of unknown origin leaves the HuC unavailable. After resume
the WOPCM and HuC are lost and a fresh authentication runs.

HuC failure never fails GT1, which keeps publishing its engines without HuC.
Linux also continues when authentication is rejected or the status bit times
out. Three cases are NARF deviations where Linux fails the GT or the probe:
- a missing, revoked or malformed image;
- a HuC object that cannot be staged, after which the runtime starts the media
  GuC again without HuC;
- a locked WOPCM that names no HuC loading agent or has no room below its
  GuC base, so the HuC is never uploaded.
A HuC DMA that never completes is a uC load failure in Linux too, and it loses
the media GuC. So does a lost status register or an unresolved CT request. As
on TGL, a GT without a VCS gets no HuC.

The media HuC object is reclaimed after the media GuC's verified stop (MIA in
reset, DMA idle): only that DMA and the media GuC's AUTHENTICATE_HUC read it,
and NARF issues no GSC authentication. TGL keeps its sticky exposure until full
Gen12 reset. The GSC module is split accordingly. The HuC parts are now
production and lose the dead-code allowance. The GSC image, its load batch and
the HECI/MKHI/PXP packets move to `intel_gpu_gsc_heci.rs` and keep it. GSCCS,
GSC firmware load, Wa_14015076503 and GSC HuC authentication are the GSC
sections below.

GT1's topology now follows Linux for its L3 banks too. xe_gt_topology_init
runs load_l3_bank_mask on the media GT. xe_gt_topology_report_l3 keeps a media
GT's entry before media version 30, as part of the existing ABI. GT1's
MIRROR_FUSE3 and XEHP_FUSE4 are read with its other fuses and expanded by the
graphics 12.70 rule: each GT_L3_EXC_MASK bit selects a two-bank pair, repeated
every four bits for each MEML3_EN node. The 8-byte DRM_XE_TOPO_L3_BANK entry
sits between GT1's compute and EU entries. Mesa reads only gt_id 0, so this
changes no Mesa result. GT0's own L3 bank entry is "Main-GT L3 bank topology
entry" below.

New fixtures register under `intel_gpu_media_gt`:
- `smoke_media_huc_guc_upload_auth_reload_and_xe_query` covers the WOPCM, DMA,
  CT and status sequence, the query routing and wire, the verified stop, and
  recovery adoption and resume re-authentication.
- `smoke_media_huc_failures_keep_gt1_published` covers rejection, ACK without
  status (with GT0's bit set as a decoy), an inherited bit and a blocking
  locked WOPCM. In each case GT1 publishes and a user job retires.
- `smoke_media_huc_option_staging_refusals_and_lost_status` covers both
  options' grammar, profiles, image validation, registry refusals, a TGL image
  on GT1, the unallocatable-HuC fallback, the option-off sequence and a lost
  status register.
- `smoke_media_gt_topology_l3_bank_mask_follows_xe_gt_topology` checks the L3
  rule.

The GT1 topology fixtures now include the L3 entry, and the media-staging
fixtures pass the new HuC argument. The TGL HuC fixtures are unchanged apart
from routing an MTL-profile AUTHENTICATE_HUC to the media model. The runtime's
firmware acquisition, staging fallback and adoption bookkeeping were reviewed
manually. None of these fixtures is physical Intel, Mesa or codec evidence.

Review against Linux found the following:
- The load order follows `xe_uc_load_hw`: HuC DMA before the GuC upload, and
  `xe_huc_auth(VIA_GUC)` after the default LRCs.
- The HuC version query follows `query_uc_fw_version`: pad, pad2 and reserved
  refuse with EINVAL, as does an unknown type, and a missing GT1 or a HuC that
  is not running is ENODEV.
- GT1's L3 bank entry follows `load_l3_bank_mask` for graphics 12.70:
  `GT_L3_EXC_MASK` (`XEHP_FUSE4` 6:4) pairs per node, repeated for each
  `MEML3_EN_MASK` (`MIRROR_FUSE3` 3:0) node.
`intel_gpu_gsc_heci` keeps the temporary dead-code allowance outside
kernel-test builds; the HuC parts of `intel_gpu_gsc` are production now.

### Display-14 power services: DMC, DC_off and lit-panel DC5/DC6 — release gates recorded

This slice gives Meteor Lake and Arrow Lake a production display power path
(§12.1). The MTL DMC container is acquired from the firmware registry,
validated under display-14 rules, loaded, verified and restored across system
suspend. The `DC_off` well is reference-counted: KMS sessions, legacy guards,
display recovery, format refresh, the MTL modeset, PSR notifications and every
full-AUX panel-backlight conversation exit DC5/DC6 before touching hardware.
Re-entry happens 17 ms after the last release, from a lock-free service task.
Every firmware, validation, verification or `DC_STATE_EN` write failure fails
closed in DC0. PCI runtime autosuspend with a lit iGPU panel stays refused,
matching Linux's display wakeref, so DC5/DC6 is the lit-panel idle power path.
Gen12 DMC parsing, loading and the inert §13 seam are unchanged.

DC6-safety audit. Every display-MMIO path that can run on display 14 while
DC5/DC6 entry is allowed either holds a DC_off reference or is unreachable in
that state:

| Path | Reference or proof |
| --- | --- |
| Display IRQ / vblank interrupts | Unreachable: no display interrupt handler exists. GT MSI setup refuses a master with a display indication, and vblank waits are `Guard::wait_vblank`. |
| KMS flips, nonblocking FIFO, legacy page flip, DIRTYFB | `Device::session` `Guard` reference (FIFO worker and devfs both enter through it). |
| Cursor and DSB | Owners live in KMS state and run only under a `Guard`. Modeset resource setup runs under the modeset reference. |
| Color / LUT / CTM | `Guard` reference; modeset RGB-bypass initialization runs under the modeset reference. |
| Console restore/pause, display recovery, legacy PM guards | References in `quiesce`, `recover`, `legacy` and `legacy_drain`. |
| fbcon / legacy fb draws | CPU memory writes only. Scanout publication reaches PSR through `notify_scanout_dirty`, which holds a reference. |
| PSR enable / KMS inhibit / dirty notify | Gen12 probe enable never runs on display 14. Inhibit runs inside a `Guard` takeover or recovery. Notify holds a reference. KMS-owned PSR1 (`intel_gpu_psr`) enables, pauses, re-arms and disables only inside the `Guard`, `legacy_drain` and `recover` references; it holds none while active, as Linux allows DC5/DC6 with PSR1 active. |
| PWM backlight | Unreachable: `backlight_supported()` is Gen12-only. |
| Full-AUX backlight | Fixed in this slice: reference per AUX transaction, availability probe, PPS gate access and relight step. The earlier "owner installed" re-entry gate is removed. |
| HPD polling, external DP/HDMI/MST, USB-C bridge | `poll_dp_hpd_events` runs at probe under `legacy()`. `service_external_sst` returns before any guard or MMIO without a DP session. Gen12 external admission and the bridge take `legacy()`. Joined: every MTL external hardware pass (HPD poll, event handling with Type-C connect/disconnect, probe, activate, stop, and the suspend/GT-reset teardown) runs in `intel_gpu_xelpg_external::with_dc_off`, which takes one `DcUser::External` reference before its first register access and runs nothing if DC states cannot be exited. Probe registers `external_route_blocks_dc` with `register_external_live`, so a live or quarantined route, or a pass in progress, refuses re-entry between passes. |
| Frame-counter, scanline and pipe-status reads | Under `Guard`, the modeset reference or the format-refresh reference. |
| Format discovery (GETPLANE, IN_FORMATS) | `publish_console_formats` runs under Init at install, under `LegacyGuard` on console replacement, and under the publication-refresh reference. |
| debugfs / sysfs readers | No debugfs. Intel sysfs attributes (runtime power, error reports, power controls, hwmon, CCS) read cached state or GT registers only. |
| Error capture | GT-only register lists (GuC status/DMA, GDRST, GT interrupt, engine ring registers). |
| Gen12 PM core (`PmBarWindow`) | Unreachable: registered only for Gen12. |
| DC service itself | Re-entry checks run only from DC0. Loads and suspend steps hold their own references. |

Refused and remaining work:

- **FBC is limited to KMS-owned framebuffers.** `intel_gpu_fbc` drives FBC A
  on the fixed MTL/Arrow Pipe-A primary only while that plane scans out a
  KMS-owned GEM framebuffer. It is never used on the console or boot
  framebuffer. This sidesteps both blockers the earlier record named.
  - **Lifecycle:**
    - Every KMS session starts with `intel_fbc_invalidate`.
    - The latch of each flip, and of each DIRTYFB re-present, runs
      `__intel_fbc_flush`: an active FBC is nuked, and an inactive eligible
      one is activated (activation ends with a nuke).
    - Console restore, legacy guards and reset recovery disable FBC first.
      Recovery disables it through a loss-tolerant view, so the inherited
      fetcher inventory never sees this driver's FBC.
    - An FBC this driver did not activate is never touched, and KMS takeover
      still refuses it.
  - **Eligibility** is display 14's `intel_fbc_check_plane`: XRGB8888 and
    similar formats only (the XR30 input is refused); no PSR1 (Wa_14016291713;
    no stepping readout, so refused on every display 14 part); no selective
    update; the size limits. Display 14 has no FBC CDCLK term and no FBC
    watermark term, so no worker-A hook was needed.
  - **CFB:** stride and size follow `_intel_fbc_cfb_stride`, the limit
    follows `find_compression_limit`, and the base must be below 2^28.
  - **Hardware conversation:** Wa_22014263786 and wa_18038517565, `CB_BASE`,
    then the `GLK_FBC_STRIDE` override, `DPFC_CONTROL`, and a nuke.
  - **CFB placement** is in DSM, done by `intel_gpu_stolen` per
    `detect_bar2_integrated`. It excludes the first 4 KiB, the WOPCM above
    `STOLEN_RESERVED`, everything above the media GT's Wa_14019821291
    `GSCPSMI_BASE`, and every DSM page that a present DM PTE maps inside the
    CPU-mappable GGTT range `[0, BAR2 length)`. That last exclusion is the
    boot framebuffer and any other aperture writer; this driver never writes
    a DM PTE. Every placed page is then proven not system RAM
    (`narf_memory::frame::is_system_ram`), so the page allocator can never
    own it.
  - **Placement is bounded:** two ranges per function, and the CFB is
    retained for the card's lifetime. A failed placement is not retried.
  - **Cost and trade-off:**
    - The aperture scan reads one 64-bit PTE per 4 KiB of BAR2, once per
      card, at the first eligible latch.
    - A cursor- or color-only session leaves FBC off until the next flip;
      that is conservative and loses compression in the meantime.
    - Reading `GSCPSMI_BASE` without media forcewake can return 0. That is
      treated, as xe treats it, as "workaround not applied".
- **Panel replay remains unqualified** (§10). PSR1 is covered by the next
  subsection, PSR2 selective update by "Display-14 PSR2 selective update and
  frame damage".
- **Other remaining display power work:** per-well reference counts beyond
  DC_off, the xelpdp AUX power-request mechanism, display-core uninit and DC9
  at suspend, DC3CO, and display stepping. Pipe DMC programs are loaded and
  enabled with their pipes (§12.1).

Twenty-eight native fixtures cover this slice. In `drivers/gpu/intel_gpu_dmc`
there are four:
`smoke_xelpdp_dmc_parse_skips_pipe_programs`,
`smoke_xelpdp_dmc_parse_refusals`, `smoke_xelpdp_dmc_load_conversation` and
`smoke_xelpdp_dmc_disable_and_geometry`. In
`drivers/gpu/intel_gpu_dc_states` there are fifteen:
`smoke_dc_states_register_facts_pinned`,
`smoke_dc_states_write_stick_discipline`,
`smoke_dc_states_init_held_until_program_loaded`,
`smoke_dc_states_bad_firmware_fails_closed`,
`smoke_dc_states_exit_before_hardware_and_refcount`,
`smoke_dc_states_flip_during_dc6_counts_residency`,
`smoke_dc_states_stuck_write_latches_fault`,
`smoke_dc_states_suspend_resume_restore`,
`smoke_dc_states_program_loss_reloads_before_reentry`,
`smoke_dc_states_arm_gates_refuse`,
`smoke_dc_states_firmware_authority_refusal`,
`smoke_dc_states_reference_inert_without_service`,
`smoke_dc_states_audit_unreachable_display_paths_on_mtl`, `smoke_dc_states_external_route_guard_blocks_reentry` and `smoke_dc_states_external_pass_bracket_and_live_predicate`. In `drivers/gpu/intel_gpu_stolen` there are two: `smoke_stolen_discovery_decodes_pinned_fields` and `smoke_stolen_cfb_avoids_boot_fb_wopcm_and_gsc`. In `drivers/gpu/intel_gpu_fbc` there are six: `smoke_fbc_display14_eligibility_and_console_refusal`, `smoke_fbc_cfb_geometry_and_compression_limit`, `smoke_fbc_enable_activate_nuke_conversation`, `smoke_fbc_flush_nukes_on_flip_and_dirtyfb`, `smoke_fbc_disabled_before_console_reclaim_suspend_and_reset` and `smoke_fbc_inherited_enable_untouched_and_refused`. In
`drivers/gpu/intel_gpu_aux` there is one:
`smoke_intel_aux_backlight_every_register_access_holds_display_power`. These
are register-model fixtures. The physical KMS, modeset, publication, suspend
and backlight hooks are wired but are manually traced, not executed. MTL
silicon DC residency and visible-pixel acceptance remain unrun.

The one-time GGTT aperture scan that excludes boot-framebuffer pages
runs in the first eligible `present()`, under the KMS session mutex and a
DC_off reference. It is not under an IRQ-safe lock, but it is about 10^5 MMIO
reads for a 256 MiB aperture in one executor poll.

### Display14 resource transactions — release gates recorded

Qualified display14.00 (Meteor/Arrow Lake) modesets now compute and own
their display resources instead of reusing a fixed profile. The computation
transcribes Linux b90c984d: display-14 watermark latencies and SAGV block
time from the MTL latency registers (read latency 6 µs, 255-line limit),
linear/X/Tile4 levels, transition and SAGV watermarks, the 256-pixel
cursor DDB budget and the vblank prefill limit; DBUF slice selection and
MBUS joining from the ADL-P/MTL table for up to four pipes, hdisplay-weighted
pipe DDB, proportional plane DDB with level search, post-allocation checks and
the disabled-level copy workaround; minimum CDCLK from pixel rate, plane,
pipe-bandwidth and DBUF-bandwidth floors with port voltage levels; and PM
demand parameters. Gen12 watermark results are unchanged.

The commit requires every pipe, plane, cursor, DSB and FBC to be off. It
follows the source order: PM demand at max(old, new), the final CDCLK
(crawl, squash or crawl+squash through the 307.2 MHz midpoint, or a full PLL
relock when the firmware clock is unknown), DBUF slice power, MBUS join with
DBOX credits and trackers, every plane/cursor WM and DDB register, then the
new PM demand. Each step is checked by readback or acknowledgement. Any
failure restores the touched registers in reverse order. Once the pre-plane
request was acknowledged, the restore first re-raises PM demand to
max(original, new), so the demand covers every clock it restores, and programs
the original demand only after the original clock is back. A failed re-raise
stops the restore before any clock change, and the raised PM demand stays. The
pipe stays off either way. The owned modeset uses a single Pipe-A request
(primary plus budgeted hidden cursor) and reserves the HBR3 port clock it
may enable before training, which also sets voltage level 1. CDCLK may now
fall below a faster firmware clock. The multi-pipe
computation drives the Pipes B–D owner ("External outputs on Pipes B–D
beside the lit panel").

Refused or not implemented: planar formats and async-flip minimum
watermarks.
Requests outside the qualified bounds are refused before any write and keep the
inherited path. Thirteen new native fixtures cover latency decoding, levels
and refusals, vblank limiting, DBUF tables, multi-pipe DDB, CDCLK plans and
crawl acknowledgement, PM demand bracketing, a two-pipe commit, restoration and
the production modeset. One existing fail-closed fixture now pins the full
source CDCLK relock and its restoration instead of the old raise-only
writes. These are native register models; silicon acceptance is unrun.

Live repartitioning (`intel_gpu_xelpg_live`) moves this state between
configurations while listed pipes stay lit, following
`skl_commit_modeset_enables`. PM demand is raised first, and CDCLK changes
before the planes only when rising. DBUF slices power old and new together.
MBUS joins (selecting the lit joined pipe), with DBOX and tracker updates,
before any DDB growth. Lit pipes take their new DDB in reverse pipe order,
each once its target overlaps no other current allocation, and are armed
through `PLANE_SURF`/`CURBASE` after the 100 µs vblank evasion. A frame wait
follows each changed allocation while other pipes remain. The unjoin with its
vblank, the off pipes, slice power-down, a falling CDCLK and the final PM
demand come last. A changed lit pipe, an unknown firmware CDCLK, live FBC or
DSB, a foreign lit pipe, divergence from the programmed state and an
unorderable DDB move are refused before any write. A later failure undoes the
executed steps in reverse, rejoining before a formerly joined pipe regrows.
When the post-plane PM demand request was attempted, the undo re-raises
max(old, new) before anything else, as the forward pre-plane request did.

`intel_gpu_xelpg_pipes::Pipes` exposes the Pipe B-D entry described in
spec.md §3: reserve resources, program timings, let the port owner train,
enable the transcoder and arm the primary, then disable and release. The
fixed Pipe-A path is unchanged. Its KMS services still require the
single-pipe layout and refuse while another pipe is lit. The MTL external
route is the production caller (see "External outputs on Pipes B–D beside the
lit panel" below), so the temporary `allow(dead_code)` these entries carried
until that join is gone; only `Pipes::state()` stays fixture-only behind a
test gate.
Seven more fixtures cover DDB ordering and cycle refusal, MBUS join and
unjoin sequencing, adding and removing a pipe beside a lit panel, write-free
refusals, reverse undo and the pipe owner's enable/release and refusals.

SAGV is now enabled when Linux would enable it (`intel_gpu_xelpg_bw`).
`MTL_MEM_SS_INFO_GLOBAL` and the QGV point registers describe the DRAM. The
transcription of `tgl_get_bw_info` with `mtl_sa_info` derives each point's
derated and peak bandwidth per plane-count group, and `mtl_find_qgv_points`
selects the point with the least headroom that still carries the summed data
rate. PM demand `QCLK_GV_BW` then carries that point's peak bandwidth in
100 MB/s units. SAGV stays masked (0xffff) whenever SAGV is not controllable
(unsupported DRAM type, fewer than two QGV points; Linux's
`tgl_get_bw_info` marks exactly one point as not controlled and keeps the
block time for a malformed zero-point report), in which case the SAGV
block time, and so the SAGV watermarks, are zero as in `intel_sagv_init`. It
also stays masked when any active pipe has an enabled plane, or visible
cursor, whose post-DDB SAGV watermark is disabled (`tgl_crtc_can_enable_sagv`,
including the vblank prefill limit). A pipe set that allows SAGV but exceeds
every point's derated bandwidth is refused as `BandwidthExceeded`, the
source's -EINVAL. The PM demand bracket orders transitions in both paths:
masking happens in the pre-plane request and unmasking only in the post-plane
request, after every plane and DDB update. A failed commit restores the
original request. The fixed Pipe-A capture now checks the exact computed
QCLK_GV_BW rather than a constant 0xffff. Three fixtures cover QGV decode
and bandwidth math, enable/mask/refusal decisions, and all-pipes-off, live
and failure transitions. One existing latency fixture now expects the zero
block time without SAGV control.

### MTL external outputs: Type-C ownership, owned hotplug and DP SST admission — release gates recorded

This slice advances the Output support row for display version 14 (Meteor/Arrow
Lake). Sources are Linux b90c984d `intel_tc.c` (`xelpdp_tc_phy_ops`),
`intel_hotplug_irq.c`/`intel_display_irq.c` (PICA and MTP south hotplug),
`intel_display_power_well.c`/`intel_display_power_map.c` (Xe-LPDP AUX wells),
`intel_ddi.c`, `intel_cx0_phy.c`, `intel_dp_aux.c` and the register headers.

- Port map. TC1-TC4 use the source C20 blocks (0x16F200 + 0x200 per port).
  TC routes now carry the source indices: `TRANS_CLK_SEL` uses
  `intel_port_to_phy` (PHY_F-I), `TRANS_DDI_FUNC_CTL` uses enum port 3-6, and
  `DDI_CLK_VALFREQ` is written for every Cx0 port. The previous TC values (PHY
  2/3, select 9/10, no VALFREQ) were unqualified and are corrected.
- AUX power correction. Every display-14 AUX well, including DDI A eDP, is the
  channel's `XELPDP_DP_AUX_CH_CTL` bit-19 power request. The source
  `xelpdp_aux_power_well_enable`/`_disable` sequence is followed: no LT PHY,
  fixed 600 us after the request and 10 us after release. The ICL
  `PWR_WELL_CTL_AUX2` (0x45444) request the MTL modeset used before is
  removed. Display-14 AUX transports write the `skl_get_aux_send_ctl` word,
  which preserves bit 19, sets TBT_IO only for TBT-alt and polls without the
  done interrupt. Gen12 native AUX uses the same sync fields with the native
  route selected and bit 19 clear. The fixtures
  that pinned the AUX2 write now pin the corrected register.
- Type-C ownership (`intel_gpu_xelpg_tc`). Follows the source sequence: live
  mode from PICA/SDE, legacy-flag fixup, TCSS power request with IOM ready
  (500 ms) and power-state (5 ms) waits, PHY ownership, `PORT_TX_DFLEXPA1` pin
  assignment with the MTL lane table, DP-alt verification, the source rollback
  paths and disconnect. TBT-alt and pin assignment D (display gets only PHY
  lane 0) refuse with typed errors. Legacy mode is implemented but needs a VBT
  `legacy_port` fact this tree does not parse, so production declares none.
- Owned hotplug (`intel_gpu_xelpg_hpd`). PICA DP-alt/TBT sources cover TC1-TC4
  and the on-die south source covers DDI B. DDI A is never owned. Setup
  installs and reads back IMR before IER, ACKs owned IIR (PICA before SDE),
  enables per-port detection, and writes SHPD_FILTER_CNT_250 and the MTP HPD
  inversion. The per-port latches decode long and short pulses. Connector
  status is published as Connected(mode), Disconnected, ShortPulse or
  Redetect. Foreign W1C status is preserved. Authority loss makes the monitor
  uncertain. Teardown withdraws every owned source for reset/suspend. As with
  the Gen12 monitor, owned IMR bits stay masked because there is no display
  IRQ consumer.
- External DP SST (`intel_gpu_xelpg_external`). Covers DDI B (C10) and TC1-TC4
  in DP-alt or a declared legacy mode, on pipe/transcoder A. The probe connects
  Type-C, powers AUX, reads caps and the full EDID, and negotiates against HBR3
  and the TC lane limit. Over-budget streams refuse. Activation follows
  `mtl_ddi_pre_enable_dp`/`mtl_ddi_prepare_link_retrain` order through the
  shared training and ends with a fresh-frame LIVE-surface witness. A training
  fallback stops locally and retries once at the trained configuration, or
  refuses if that configuration cannot carry the stream. Stop follows
  `intel_ddi_post_disable_dp` order with every step observed. A failed stop
  quarantines the route and retains every lease. A busy pipe A (lit internal
  panel) or an active DDI refuses before any write. `MtlExternalService`
  composes hotplug handling: connect, withdraw, short-pulse revalidation and
  retrain, and re-detect. KMS suspend and GT-reset retirement tear down the
  route and the hotplug sources.

Remaining: UHBR (C20 MPLLA tables and 128b/132b), HDMI FRL, audio, the
PW_2/PW_A fuse-distribution waits and panel replay. Later sections add the
runtime caller and publication, multi-pipe repartition, HDMI TMDS, MST,
DSC/FEC, lane reversal, TBT-alt tunnels, pin assignment D, VBT legacy ports
and PSR2. Native fixtures cover these paths. They are not physical Type-C, sink or
visible-pixel acceptance.

New native tests: `drivers/gpu/intel_gpu_xelpg` (4),
`drivers/gpu/intel_gpu_xelpg_tc` (8), `drivers/gpu/intel_gpu_xelpg_hpd` (7),
`drivers/gpu/intel_gpu_xelpg_external` (8) and `drivers/gpu/intel_gpu_aux`
(1). The existing `smoke_port_register_map`, `smoke_mtl_modeset_ddi_a_full_run`,
`smoke_mtl_failclosed_powered_ddi_current_and_allones_refusal` and
`smoke_mtl_modeset_tc_ports_refuse_unqualified_route` fixtures were updated
for the corrected source values or the larger port set.

Follow-up in the same slice:

- Runtime wiring. `poll_dp_hpd_events` (probe) drains Meteor Lake hotplug
  events before the Gen12 loop, and the runtime actor's `service_external_sst`
  runs one MTL pass under the display legacy drain guard. Both reach registers
  only on a probed Meteor Lake display. The glue keeps one scanout allocation
  per BAR in the pipe-B console GGTT window, so it never remaps the internal
  pipe-A window, and reuses it whenever the next mode fits. An activated route
  is published through the ACTIVE + observer protocol under a fresh serial;
  once no route is live, exactly that serial is withdrawn.
  `external_routes_stopped` counts the MTL route. KMS suspend and GT-reset
  retirement also withdraw its publication. A native fixture drives the hook
  core `mtl_external_pass` with recorded allocation and publication. The
  `intel_gpu.rs` wrappers that read the probed controller are reviewed, not
  executed.
- DC states. Every hardware-touching external entry (hotplug poll, event
  handling with Type-C connect/disconnect, probe, activate, stop, teardown)
  runs inside one DC-off bracket in `intel_gpu_xelpg_external`. Until the
  DC-state reference service is joined, the bracket runs its closure
  directly. `route_live()` reports a live route for that service's
  DC-entry refusal.
- HDMI TMDS (`intel_gpu_xelpg_hdmi`). The 45 `mtl_c10_hdmi_tables` and the
  five TMDS `mtl_c20_hdmi_tables` entries are generated verbatim from the
  pinned source. The Cx0 enable now takes an explicit state: per-request SSC,
  C20 VDR parameters, and the legacy-mode C20 protocol switch, which clears
  the MPLLB CAL_DONE banks and waits 4 ms; the DP route now uses this for
  declared legacy ports. HDMI also gets the C10 Wa_13013502646 powerdown
  toggle and the source HDMI TX levels. The route covers DDC EDID on MTP pin
  2 for DDI B, the `intel_ddi_pre_enable_hdmi` -> `intel_ddi_enable` ->
  `intel_ddi_enable_hdmi` order with the AVI infoframe, and the
  `intel_ddi_post_disable_hdmi` stop. Typed refusals cover clocks above
  340 MHz (scrambling/SCDC not owned), FRL and the FRL-ambiguous 300/600 MHz
  clocks, clocks without a source table (the SNPS C10 and computed C20
  algorithms are not implemented; the latter needs the MTL-U/ARL-S
  `tx_misc` fact), Type-C DP-alt, and Type-C DDC (pins 9-12 are not
  representable by the shared Gen12 pin-pair encoder). The hotplug
  service selects HDMI ("MTL external outputs: HDMI selection" below).
- Thunderbolt-alt: the display side (TBT clock request, TBT DDI clock
  select, AUX TBT_IO, IO_SELECT_TBT) does not by itself carry a stream. It
  consumes a DP-IN tunnel that the USB4 connection manager or firmware has
  provisioned ("USB-C display transports").

New native tests: `drivers/gpu/intel_gpu`
(`smoke_mtl_external_hook_pass_allocates_publishes_and_withdraws`) and
`drivers/gpu/intel_gpu_xelpg_hdmi` (6).

`XeLpgModeset::modeset` raises the AUX power request before the panel EDID
read, as `intel_dp_aux_xfer` holds the AUX power domain across every transfer.

DC-state join (integrator): `with_dc_off` now holds one `DcUser::External`
reference for each hardware pass and returns `ExternalError::DisplayPower`,
running nothing, when DC states cannot be exited. The hotplug poll then
reports no event, an event pass reports `Refused`, and teardown reports the
route retained. Probe registers `external_route_blocks_dc` (a live or
quarantined route, or a pass in progress) as the DC service's liveness
predicate. A native fixture drives the real bracket and service passes over
the route model with the display-14 DC state machine on the same registers.
It checks that DC exit precedes the first pass write, that a live or
quarantined route refuses DC6, that DC6 re-enters 17 ms after a verified
stop, and that a failed exit touches no route register. On Gen12,
`routes_stopped()` can still report a transient "not stopped" when two callers
contend for the service's `try_lock`. The Gen12 hook paths otherwise return
before any register access.

### MTL external outputs: HDMI selection, GMBUS pin correction and HDMI 2.0 scrambling — release gates recorded

This slice continues the Output support row for display version 14. Sources
are Linux b90c984d `intel_ddi.c` (`intel_ddi_init`, `intel_ddi_enable_hdmi`,
`intel_ddi_disable_hdmi`), `intel_bios.c` (`init_vbt_missing_defaults`,
`map_ddc_pin`), `intel_hdmi.c`, `intel_gmbus.c`/`intel_gmbus.h`,
`intel_pch.c`, `drm_edid.c` and `drm_scdc_helper.c`.

- DP or HDMI. `MtlExternalService` owns one `MtlRoute`, either the DP SST
  route or the HDMI TMDS route, and publishes both through the same
  `Activated` outcome, ACTIVE/observer serial, and suspend/GT-reset
  retirement. Linux decides what a port carries from its VBT child device
  (`intel_ddi_init`: DP, HDMI, and for Type-C "legacy" meaning neither USB-C
  nor TBT). This tree has no VBT parser, so the facts come from an explicit
  `MtlPortPolicy`. Production uses `NO_VBT`. Under it, DDI B carries DP and
  HDMI (the same default `init_vbt_missing_defaults` gives), and TC1-TC4
  carry USB-C DP-alt only. Linux creates no Type-C encoder at all without a
  VBT, so no legacy Type-C port and no Type-C HDMI exist until a board
  declares one. A declaration also derives the hotplug monitor's legacy SDE
  sources. `NO_VBT` gives exactly `MtlHpdConfig::TYPE_C`. In Linux a dual
  port gets both connectors and each detects on its own: DP needs a DPCD,
  HDMI needs a digital DDC EDID. With one owned route the order is DP
  first, then HDMI only when the DPCD read failed. Any other DP failure
  (EDID, bandwidth, Type-C) refuses without DDC traffic. HDMI never runs
  over DP-alt or TBT-alt. A short pulse leaves an HDMI route alone, since
  `intel_hdmi` has no hpd_pulse. Redetect stops and releases the route,
  then reconnects in the live mode the route was connected in. That is a
  superset of `intel_hdmi_reset_link`.
- GMBUS pin correction (shared Gen12). `PinPair` encoded DDI A..F as
  GMBUS pins 2..7, so Gen12 DDC selected the neighbouring wires. It now
  carries the `GMBUS_PIN_*` numbers: DDI A/B/C are 1/2/3 and TC1-TC6 are
  9-14. `GmbusPinTable` holds the four tables `get_gmbus_pin` selects:
  icp for PCH_TGP and PCH_ADP, then dg1, dg2, and mtp for Meteor Lake and
  later. `gen12_ddc_pin` follows `intel_hdmi_default_ddc_pin`: the icl
  mapping on TGL/ADL-P/ADL-N and the adls mapping on ADL-S. A DDI the
  platform lacks refuses. Meteor Lake DDI B uses pin 2 ("dpb"). A declared
  legacy TCn uses pin 8 + n, the pin Linux takes from the VBT through
  `adlp_ddc_pin_map`; the no-VBT `phy + 1` formula is not wired to Type-C
  in `gmbus_pins_mtp`. The Type-C DDC refusal is lifted. The MTL route reads
  EDID through the shared GMBUS transport as `drm_do_probe_ddc_edid` does:
  one INDEX-cycle transfer per block, segment 0 only.
- HDMI 2.0 above 340 MHz. Sink capability follows
  `drm_parse_hdmi_forum_scds` over the HF-VSDB and the HF-SCDB. The
  scrambling decision follows `intel_hdmi_compute_config`: scramble when
  the sink supports it and either it accepts low-rate scrambling or the
  clock is above 340 MHz, with the 1/40 ratio above 340 MHz. A clock above
  340 MHz refuses if the sink declares no scrambling or a lower maximum;
  clocks above the 600 MHz source maximum refuse too. The source sets
  `TRANS_DDI_HDMI_SCRAMBLING` and `TRANS_DDI_HIGH_TMDS_CHAR_RATE`. The sink
  gets the `drm_scdc` ratio write (then 1 ms) and the scrambling write
  after the transcoder and before the DDI buffer, and is reset before the
  transcoder stops. This covers C10 497.75/592/593.407/594 MHz and C20
  594 MHz. Linux only logs an SCDC failure; here a stream that needs
  scrambling fails activation and is stopped locally. FRL stays refused.

Remaining: HDMI FRL, audio, deep colour and YCbCr 4:4:4. The VBT parser,
E-DDC, the computed C10/C20 HDMI PLL states, YCbCr 4:2:0 and the DC-state
join are later sections. Native fixtures cover
these paths. They are not physical sink or visible-pixel acceptance.

New native tests: `drivers/gpu/intel_gpu_xelpg_external` (5),
`drivers/gpu/intel_gpu_xelpg_hdmi` (3), `drivers/gpu/intel_gpu_gmbus` (1)
and `drivers/gpu/intel_gpu`
(`smoke_mtl_external_hook_pass_publishes_and_retires_hdmi_route`). These
were intentionally corrected: `smoke_pin_pair_round_trip`,
`smoke_edid_read_program_layout`, `smoke_transport_pin_pair_selection`,
`smoke_hdmi_1080p_connect_no_scdc_traffic` (it now pins pin 2),
`smoke_hdmi_source_family_arb_slots_and_missing_foreign_metadata_refusal`
(ADL-S has no DDI B), `smoke_mtl_hdmi_pll_tables_and_typed_refusals` and
`smoke_mtl_hdmi_probe_refusals_before_mmio`.

### VBT parser, its first consumers and the Gen12 DDC corrections — release gates recorded

This slice continues the Output support row. Sources are Linux b90c984d
`intel_bios.c`, `intel_vbt_defs.h`, `intel_opregion.c`, `intel_rom.c`,
`drivers/pci/rom.c`, `intel_ddi.c` (`intel_ddi_init`), `intel_dp_aux.c`,
`intel_hdmi.c`, `intel_cx0_phy.c`, `intel_gmbus.c`, `drm_edid.c` and
`drm_scdc_helper.c`. Struct offsets were checked against a host compile of
`intel_vbt_defs.h`.

`intel_gpu_vbt` validates a VBT as `intel_bios_is_valid_vbt` does and walks the
BDB blocks as `find_raw_section` does. A block that runs past `bdb_size` ends
the walk, and the MIPI sequence v3 block uses its u32 size. Short blocks are
zero padded to their structure size, as `init_bdb_block` pads them. The parser
decodes the general features (`enable_ssc` and the DP SSC bits), the child
devices (`child_device_size_valid`, DVO port, AUX channel, DDC pin, the
Type-C, TBT and dedicated-external bits by BDB version, DP dual mode, HDMI
level shifter and max TMDS clock, lane reversal, DP max rate and lanes) and the
driver features. It also decodes the LFP options panel type, the eDP block
(bpp, PPS delays, link rate, lanes, pre-emphasis, voltage swing, low vswing,
max rate, DSC disable) and the LFP power block's per-panel `hobl` bit (BDB
232+, block offset 54), PSR and PSR2 wake times and enable, and the LFP
backlight. The per-platform tables cover TGL, ADL-S, ADL-P (display 13) and MTL
(display 14): `dvo_port_to_port`, `map_aux_ch`, `map_ddc_pin`, the default DDC
pin, `intel_phy_is_tc` and the port masks. `Vbt::encoders` reproduces the
encoder set `intel_ddi_init` builds: port and AUX claims, the Type-C legacy
rule, and the `intel_hdmi_ddc_pin` validity and claim checks.

Discovery follows `intel_opregion_setup`. Probe reads ASLS (PCI config 0xFC)
and copies the 8 KiB OpRegion read-only through the kernel direct map. It
does so only after every page proves to be known RAM; the boot map registers
ACPI NVS as known RAM. So no memory-subsystem change was needed, and device
MMIO cannot be reached. The RVDA VBT (OpRegion 2.0 physical, 2.1+ relative to
ASLS, bounded by the 16-bit VBT size) comes first, then mailbox #4, which is
bounded at the ASLE extension when mailbox #5 exists. Unlike Linux, the
OpRegion is never written. SPI flash is a discrete-only source. The PCI option
ROM needs the expansion-ROM BAR assigned and enabled, which the bus layer does
not do. So the ROM search (`pci_get_rom_size`, `oprom_get_vbt`) is parsed and
tested but not wired, and production discovery is OpRegion only.

Consumers. On Meteor Lake, `MtlPortPolicy::from_vbt` turns the encoder set into
the DDI B and TC1-TC4 declarations: DP, the HDMI connector with its DDC pin, and
legacy Type-C. Ports the route cannot drive as declared fail closed. These are
DSI and eDP encoders, a VBT AUX channel other than the port's own, lane reversal
(the route never sets PORT_REVERSAL), and a dedicated-external Type-C port. The
hotplug monitor takes the VBT's legacy sources before its first poll. DP SSC
now follows `intel_cx0pll_update_ssc`: it is on only when `intel_panel_use_ssc`
(the VBT `enable_ssc`, on without a VBT) and the sink's `DP_MAX_DOWNSPREAD_0_5`
both hold. Without SSC the C10 state takes the non-SSC form (PLL bytes 4..8
zeroed) and PORT_CLOCK_CTL leaves SSC_ENABLE_PLLB clear. This intentionally
changes sinks without downspread, which used to get SSC unconditionally. Gen12
HDMI takes its DDC pin from the VBT when the VBT declares an HDMI connector on
the DDI. With no VBT, Meteor Lake keeps `NO_VBT` (`init_vbt_missing_defaults`)
and Gen12 keeps `gen12_ddc_pin`. The eDP, PSR and backlight panel facts are
exposed (`edp_panel`, `psr_panel`, `backlight_panel`, `panel_type`) for the
panel and PSR owners; the eDP HOBL / low-vswing bits are consumed by the
Gen12 combo-PHY table selection (`VbtEdpSignal`, installed at probe), the
PSR facts by the display-14 PSR gate and `edp.bpp` by the 6 bpc pipe limit
(both below).

Gen12 DDC corrections. The Gen12 HDMI session now runs on `GmbusBus`, whose
new `xfer` is `do_gmbus_xfer`. Each message ends in the wait phase so the next
starts with a repeated START, and one STOP follows the last. Index transfers
use CYCLE_INDEX with CYCLE_WAIT, or GMBUS5 with 2BYTE_INDEX_EN cleared after
the data phase. A NAK on the first message is retried once. The old engine ran
each program as one STOP transfer and then waited for idle. It wrote GMBUS5
without the enable bit, and it read SCRAMBLER_STATUS before scrambled data
flowed. Indexed programs previously carried CYCLE_INDEX without CYCLE_WAIT,
which never enters the wait phase the transport then waited for. EDID follows
`drm_do_probe_ddc_edid`, with the E-DDC segment pointer chained ahead of
blocks 2 and 3. The MTL HDMI route now reads those blocks too. SCDC follows
`intel_hdmi_handle_sink_scrambling`: the ratio, at least 1 ms, then scrambling.
Gen12 records the scrambler status after the stream runs and resets SCDC on
disconnect; MTL uses the same helper.

Remaining: VBT consumers for the panel (PPS, eDP link, backlight) and for
the VBT `max_tmds_clock`, DP rate and lane caps; driving a VBT AUX remap or a
dedicated-external Type-C port; PnP-ID and OpRegion (SWSCI)
panel-type selection; the PCI option ROM mapping; Gen12 port existence from
the VBT; Gen12 SCDC for scrambling-capable sinks at or below 340 MHz, as Linux
writes them; and GMBUS burst reads above 511 bytes. Native fixtures cover all
of this; it has not been tested against physical VBTs or sinks.

New native tests: `drivers/gpu/intel_gpu_vbt` (16),
`drivers/gpu/intel_gpu_xelpg_external` (5), `drivers/gpu/intel_gpu_gmbus` (1)
and `drivers/gpu/intel_gpu_hdmi` (1). These were intentionally corrected:
`smoke_transport_edid_base_block_read`,
`smoke_transport_segment_and_index_reads`,
`smoke_transport_two_byte_index_uses_gmbus5`,
`smoke_transport_nak_refusal_and_recovery` and
`smoke_transport_scdc_write_then_read`. They now follow the `do_gmbus_xfer`
conversations, and the first four also had a GMBUS0 select of 3 left over from
before the pin renumbering. On the Gen12 side,
`smoke_hdmi_1080p_connect_no_scdc_traffic` and
`smoke_hdmi_4k60_scdc_scrambling` follow the Linux EDID and SCDC sequences, and
`smoke_hdmi_edid_segment_pointer` checks the chained segment write.
`smoke_hdmi_scdc_verify_failure` became
`smoke_hdmi_scdc_status_sampled_after_stream`.

Integration of the HDMI-selection, GMBUS and VBT slices: both ride the
DC-state join, so every HDMI hotplug, probe and activation pass holds the
`DcUser::External` reference through `with_dc_off`. A refused DC exit
reports a DP route error carrying `ExternalError::DisplayPower`. The new
`MtlRoute::release`, like the protocol release methods, allows
`clippy::result_large_err`.

### Display-14 PSR1 under KMS ownership — release gates recorded

The fixed MTL/Arrow Pipe-A KMS owner no longer leaves PSR off for the whole
ownership period. `intel_gpu_psr` implements display 14's PSR1 from the
pinned `intel_psr.c`, and the owner drives it through the same session
discipline as FBC.

- **Enable:** after the first latched KMS GEM framebuffer. The sink is read
  once: the PSR capability, eDP `SET_POWER_CAP`, the max-resync latency (8
  when unreadable), ALPM, TPS3 and the `NO_PSR` OUI quirk. Qualification is
  `intel_psr_compute_config` for display 14: no interlace, a valid setup time
  within `vtotal - vdisplay - 1` lines of the live transcoder-A timing. The
  enable is `intel_psr_enable_locked`: an IIR error check, the sink
  (`DP_PSR_EN_CFG` CRC, then with `DP_PSR_ENABLE`, then `DP_SET_POWER` D0),
  then the source (`PSR_MASK`, `psr_irq_control`, Wa_14015648006). Every
  refusal precedes the first write.
- **Activation and exit:** `hsw_activate_psr1` runs when the session ends
  (`Guard` drop), and only if every frame change the session began has
  latched and the KMS framebuffer is on screen. Every session start runs
  `intel_psr_exit` and waits for idle (2 s bound), so flips, DIRTYFB
  re-presents, cursor and color/DSB arms never run against self-refresh.
  Re-arm happens only from an idle status. This replaces Linux's frontbuffer
  invalidate/flush and pipe-update idle wait with one bracket.
- **Disable:** `intel_psr_disable_locked` (exit, idle, Wa undo,
  `DP_PSR_EN_CFG` 0) runs before console restore, surface restore, legacy
  drain, suspend quiesce and reset recovery. Recovery uses the loss-tolerant
  view.
- **Errors:** there is no display interrupt handler, so `TGL_PSR_ERROR` is
  polled in `TRANS_PSR_IIR` at every pause and re-arm. An error disables PSR,
  wakes the sink and latches `SinkNotReliable`, as `intel_psr_handle_irq`
  does. Enable refuses while `GEN8_DE_MISC_IER` could deliver
  `GEN8_DE_EDP_PSR`.
- **FBC policy:** PSR wins. Wa_14016291713 refuses FBC with PSR1 on display
  14.00 A0–C0, and there is no stepping readout, so FBC is disabled before
  the PSR sink is enabled and stays refused while PSR is enabled. A latched
  PSR refusal lets the next latch activate FBC.
- **No VBT:** Linux gates eDP PSR on the VBT's `psr.enable` and takes TP
  times from it. This driver uses the sink and source qualification, the
  `psr_safest_params` TP times (2500 µs) and link-off mode
  (`link_standby` false on display >= 12).
- **DC states:** PSR holds no DC_off reference while active. Every PSR
  conversation runs inside the KMS, legacy or recovery reference.
- **Gated input:** Wa_14015648006 needs `wm_level_disabled` from
  `skl_wm_check_vblank`, which the watermark lane does not compute yet. Until
  it calls `intel_gpu_psr::register_wm_level_disabled`, PSR is refused with
  `WmLevelUnknown` (retried at each latch) rather than guessed. Production
  PSR is therefore wired but inert on hardware today.
- **Probe:** Gen12 probe-time PSR no longer runs on display 14; it would
  have programmed the TGL `PSR2_CTL` layout.
- **Remaining:** early transport; Panel Replay stays refused. PSR2
  selective update and the damage clips that drive it are "Display-14 PSR2
  selective update and frame damage" below.

Twelve native fixtures are registered under `drivers/gpu/intel_gpu_psr`.
Six are register/sink models:
`smoke_psr_sink_caps_decode_and_refusals`,
`smoke_psr_qualify_follows_compute_config`,
`smoke_psr_enable_conversation_is_linux_ordered`,
`smoke_psr_enable_refuses_before_any_write`,
`smoke_psr_pause_resume_and_disable_sequences` and
`smoke_psr_wm_level_provider_registry`. Six drive the production
`Device`/`Guard` path on x86_64:
`smoke_psr_kms_enables_after_latch_and_activates_at_session_end`,
`smoke_psr_kms_flip_and_dirtyfb_exit_before_arm_and_rearm_after_latch`,
`smoke_psr_kms_color_and_cursor_rearm_only_after_their_latch`,
`smoke_psr_kms_disabled_before_console_legacy_suspend_and_reset`,
`smoke_psr_kms_wins_over_fbc_in_both_directions` and
`smoke_psr_kms_refusals_leave_zero_psr_traffic`.

### Display-14 pipe DMC — release gates recorded

Display 14 now loads and enables the per-pipe DMC programs as the pinned
`intel_dmc.c` does, instead of skipping them and refusing DC re-entry on any
pipe DMC enable.

- **Load:** `intel_gpu_dmc` parses the pipe programs of `mtl_dmc.bin`. Each
  must keep its MMIO table in `ADLP_PIPE_MMIO` and its payload in its slot
  window (A 0x90000, B 0x98000, C 0x52000, D 0x59000). The windows are NARF
  policy. They come from the shipped `mtl_dmc.bin` v2.23, whose
  `DMC_SSP_BASE` stack tops sit 0x40 below each window end; the pinned tree
  bounds no program RAM. An out-of-window pipe program is skipped, its pipe
  DMC is never enabled, and DC behaviour stays as before. Every accepted program is
  streamed with the main program, pipe events disabled, behind
  Wa_16015201720, and verified.
- **Enable and disable:** `pipe_lit_for_bar` and `pipe_dark_for_bar` are the
  pipe-lifetime hooks. Enable is `intel_dmc_enable_pipe` for display 14
  (pipe C/D table re-apply, verify, `PIPEDMC_ENABLE_MTL`); disable clears the
  bit. KMS install reports the owned Pipe A lit. The Pipe B–D owner and the
  MTL modeset own their calls; their files are not changed here.
- **Reload and suspend:** every (re)load re-enables the lit pipes under its
  Load reference. Suspend clears the enables before the program disable, and
  the post-resume reload restores them.
- **DC gate:** re-entry is refused only for a pipe DMC this driver did not
  enable, and re-entry verifies only the main program
  (`assert_main_dmc_loaded`).
- **Stricter than the tree:** the per-slot payload windows, and a pipe
  program that fails verification is not enabled.
- **Remaining:** pipe DMC event configuration (DC balance, PKG C-state
  blocking, flip queues) is display 20+ or unused here. The Pipe B–D and
  modeset owners must call the hooks before their pipes are DC-safe.

Fixtures: in `drivers/gpu/intel_gpu_dmc`, `smoke_xelpdp_dmc_parse_skips_pipe_programs` is
replaced by `smoke_xelpdp_dmc_parse_bounds_pipe_programs`;
`smoke_xelpdp_dmc_load_conversation` and
`smoke_xelpdp_dmc_disable_and_geometry` now expect the pipe programs; and
`smoke_xelpdp_pipe_dmc_enable_disable` is new. In
`drivers/gpu/intel_gpu_dc_states`, `smoke_dc_states_pipe_dmc_follows_pipe_lifetime`
is new.

### Display-14 PSR inputs, VBT gate and off-path FBC carve — release gates recorded

This slice joins the display-14 power pieces so that PSR1 can run on
hardware, and clears four review follow-ups. It supersedes the "No VBT" and
"Gated input" bullets of the PSR1 subsection above.

The Wa_14015648006 input now exists. The display-14 watermark code computes
`skl_wm_check_vblank`'s `wm_level_disabled` where it computes the levels.
The value is true when the highest level whose prefill fits vblank is below
level 5. Zero-latency levels are skipped as Linux skips them, so a latency
table that ends early also reports true. The owned Pipe-A profile records the value for its
layout (linear/X or Tile4), from the same primary and always-budgeted cursor
lines the transaction's vblank check used. Every proof that the Pipe-A
watermarks are programmed publishes the value: profile capture, and the
retained primary owner's check, complete and rollback. A transaction about
to write, a pending image or a failed proof publishes "unknown". Display-14
KMS install registers the publication as PSR's provider, and PSR
qualification re-proves the programmed watermarks just before reading it, so
the answer is never stale. While PSR is enabled, a staged Tile4 or linear
primary image applies `wm_optimization_wa` as Linux's pre- and post-plane
updates do: the bit is set before a disabling image latches and cleared
after a full-level one; a rolled-back stage restores the current value.

eDP PSR is now gated on the VBT as `psr_global_enabled` does. The panel is
`get_panel_type`'s VBT index for the port-A child (`panel_type2` for an LFP2
handle), falling back to 0. Its `psr.enable` must be set. Without a VBT,
Linux leaves `psr.enable` false: `init_vbt_missing_defaults` sets no panel
PSR fact, and the feature blocks that would set it are absent. PSR is
therefore refused without a VBT, replacing the earlier `psr_safest_params`
behaviour. A 0xFF panel type
is refused because PnP-ID matching is not implemented. The refusal comes
before any sink or source access and is retried at each latch. The TP1 and
TP2/TP3 wake times and the idle-frame floor now come from the VBT's PSR
table (`intel_psr1_get_tp_time`, `psr_compute_idle_frames`). With a VBT but
no PSR block they are Linux's zeroed values. Probe installs these facts on
Meteor Lake.

PSR therefore enables on hardware when all of the following hold. The part
is display 14 with the KMS-owned Pipe-A eDP, after its first latched KMS
framebuffer. The OpRegion VBT enables PSR for the panel. The sink reports
PSR without the `NO_PSR` quirk and has `SET_POWER_CAP`. The timing is
progressive with a setup time that fits. The programmed Pipe-A watermarks are
the ones the owned modeset computes: profile capture needs display 14.00,
pipes B–D off, and the joined single-pipe DDB, DBUF, MBUS, PM demand and
CDCLK it expects. No PSR error is latched, `GEN8_DE_EDP_PSR` cannot reach the
CPU, and no PSR was inherited. With firmware-programmed watermarks that differ
from NARF's, or with an external pipe lit, PSR stays refused with
`WmLevelUnknown` and is retried at each latch.

The FBC CFB carve no longer runs in `Guard::present`. A resumable
`stolen::Carve` reads at most 1024 GGTT entries per step. A spawned job
holds the KMS mutex for each step and yields between steps, then places the
CFB outside the mutex. The present path only polls a non-blocking
`CarveSlot`: while the job runs FBC stays off and is not refused, and the
next eligible latch after it finishes activates FBC. Lost access abandons the
job, and the next latch launches it again. The survey stays valid because
this driver never writes a DM PTE.

The Wa_14019821291 GSC carve now follows Linux's
`media_gt && XE_GT_WA(media_gt, 14019821291)`. It applies only when the media
`GMD_ID` names a media GT that `xe_pci.c` would create, in 13.00–20.00
(13.00, 13.01 or 20.00). Otherwise `GSCPSMI_BASE` is neither read nor used.

The SAGV fixture now pins Linux's uncontrolled case of exactly one QGV point.
Zero points stays NARF policy and is documented as a divergence. Linux would
report SAGV as enabled and fail every SAGV-capable state in
`mtl_find_qgv_points`; NARF keeps SAGV masked, which can cost power but
never refuses a display configuration.

Fixtures. New in `drivers/gpu/intel_gpu_xelpg_wm`:
`smoke_xelpg_wm_level_disabled_follows_skl_wm_check_vblank`,
`smoke_xelpg_wm_check_vblank_returns_its_level_decision`,
`smoke_xelpg_wm_profile_value_matches_transaction_vblank_check` and
`smoke_xelpg_wm_pipe_a_provider_publishes_and_registers`. New in
`drivers/gpu/intel_gpu_psr`: `smoke_psr_vbt_gate_precedes_every_other_check`,
`smoke_psr_vbt_wakeup_times_and_idle_frames_reach_psr_ctl`,
`smoke_psr_vbt_facts_follow_intel_bios_init_panel`,
`smoke_psr_wm_optimization_wa_follows_pre_and_post_plane_update`, and on the
production `Device`/`Guard` path
`smoke_psr_kms_production_wm_provider_qualifies_and_enables`,
`smoke_psr_kms_wm_level_disabled_takes_wa_14015648006`,
`smoke_psr_kms_vbt_refusal_precedes_sink_and_source` and
`smoke_psr_kms_vbt_wakeup_times_reach_psr_ctl`. New in
`drivers/gpu/intel_gpu_stolen`:
`smoke_stolen_carve_survey_is_chunked_and_places_like_one_shot`,
`smoke_stolen_carve_slot_polls_without_blocking` and
`smoke_stolen_gsc_carve_follows_media_gt_workaround`. New in
`drivers/gpu/intel_gpu_fbc`:
`smoke_fbc_kms_present_only_polls_carve_and_activates_after_it`. The
existing PSR fixtures now pass a VBT that enables PSR with 2500 µs wake
times, so their expected `PSR_CTL` values are unchanged.

The carve job reads
only GT-side registers: the GGTT PTE array, GGC, STOLEN_RESERVED, the media
GMD_ID and GSCPSMI_BASE, and PCI config. It holds the KMS mutex per chunk with
no DC_off reference, yields between chunks and places outside the mutex. Lost
access abandons the slot, and the next present relaunches it.

Remaining: EDID PnP-ID panel selection, so that a 0xFF VBT panel type can
enable PSR, and a hardware run of the chain. The production carve job and
the `Physical` VBT and provider hooks run only on hardware; the native
fixtures model the `Carve`, `CarveSlot`, provider and VBT facts they
compose.

### External outputs on Pipes B–D beside the lit panel — join recorded

This join connects the display-14 resource owner, the external routes and the
pipe DMC so an external monitor runs next to the lit laptop panel. Sources are
Linux b90c984d: `intel_display.c` (`intel_atomic_commit_tail`,
`skl_commit_modeset_enables`, `hsw_crtc_enable`, `hsw_crtc_disable`,
`hsw_configure_cpu_transcoder`, `intel_pre_update_crtc`, `intel_update_crtc`),
`intel_ddi.c` (`mtl_ddi_pre_enable_dp`, `intel_ddi_pre_enable_hdmi`,
`intel_ddi_enable`), `intel_crtc.c` (`intel_pipe_update_start` and `_end`),
`intel_vblank.c::intel_vblank_evade`, `intel_dmc.c` (`intel_dmc_enable_pipe`
and `intel_dmc_disable_pipe`), `intel_pmdemand.c` and
`intel_display_power_map.c` (`xelpdp_pwdoms_pw_2` carries pipes B–D).

The external DP and HDMI routes no longer take Pipe A, and they no longer
refuse while the panel is lit. Each activation first checks, with reads only,
that the target DDI and its PLL are off. It then picks the lowest Pipe B–D
whose transcoder, primary plane and transcoder function are all off, and
adopts what Pipe A runs. A dark Pipe A needs nothing. A lit Pipe A must be the
owned panel profile of the pass's display context: the MTL modeset records the
mode whose resource profile it established, and the runtime passes it in.
Refusals are typed and come before the first write: `NoFreePipe`, `PipeBusy`
for a lit Pipe A that cannot be adopted, `PortBusy`, and `Pipe(PipeRefusal)`
from the owner's admission. Admission covers WM, DDB, CDCLK and bandwidth
limits and the live transaction's idle preconditions, including FBC and DSB.

The enable follows Linux's order. The pipe's power wells come first (PW_1,
PW_2 and the pipe's own well). Then the pre-plane resource transaction runs
with the panel kept lit, and `intel_dmc_enable_pipe` follows. The port
sequence of `mtl_ddi_pre_enable_dp` or `intel_ddi_pre_enable_hdmi` then
programs the chosen transcoder's `TRANS_CLK_SEL`, `TRANS_DDI_FUNC_CTL`,
`DP_TP_CTL`, M/N or AVI infoframe. After that come the source size, the
timings, the per-pipe RGB bypass and the no-DPT plane chicken, then the
function enable, the transcoder enable and, for HDMI, SCDC and the DDI
buffer. The primary is armed last. A DP training fallback stops only the port
and retries on the same reservation.

The stop reverses this. The primary goes off, then (for HDMI) the sink
scrambling is reset. The transcoder goes off and the port side stops. Then
`intel_dmc_disable_pipe` runs, and the post-plane repartition gives Pipe A its
whole profile back, which the KMS fixed-profile capture accepts again. A
failed activation takes the same stop path. A release that fails leaves the
route quarantined with its reservation. The panel is never stopped or
replaned: its plane registers are only re-armed with the same surface.

PM demand now uses the route's port clock, as Linux uses
`crtc_state->port_clock`: the negotiated DP link rate, chosen before
training, or the HDMI TMDS clock. Negotiation picks the lowest rate that
carries the stream, and the fallback ladder never raises it, so a fallback
that still carries the stream trains at the reserved rate with fewer lanes.
The owned panel keeps its HBR3 reservation, because the KMS profile checks
the acknowledged demand against it. That over-request is the documented
fallback.

Every arm write now runs inside vblank evasion with local interrupts masked
by `narf_lib::sync::without_interrupts`. This covers the live update of lit
pipes and the Pipe B–D primary arm. Interrupts are masked from the scanline
sample that leaves the window through the arm writes, and unmasked only while
waiting inside the window. The MTL modeset reports Pipe A dark after its crtc
disable and lit before its port PLL. The route's pipe travels with the
activation outcome and the publication, and `active_external_pipe()` reports
it for the active image.

`routes_stopped()` and `route_live()` now read the route presence the
service publishes when each pass ends, so a pass that only holds the service
no longer looks like "not stopped" to Gen12 relight, device PM or the DC
gates. `external_route_blocks_dc()` still reads the service itself: a busy
service, or a live or quarantined route, keeps DC5/DC6 refused.

Remaining: the external is refused next to an inherited, non-owned panel
layout, and only one external route runs at a time. The panel's KMS, cursor,
FBC/DSB and PSR beside a lit external are "The panel's KMS services beside a
lit external" below. Production pipe-DMC calls are covered by the DC
service's own smokes and are inert without that service.

Fixtures and tests: `ExtFake` now models TRANSCONF, frame counter and LIVE
surface for every pipe, the PM demand and DBUF acknowledgements, the CDCLK
crawl acknowledgement and WM latencies, and `light_panel()` commits the owned
panel profile. External-route smokes that pinned Pipe A now pin Pipe B,
because the route never drives Pipe A. The DDI B smoke now requires PW_2,
which carries pipes B–D on display 14. The HDMI busy-fetcher case now refuses
through the owner's typed admission. The new smokes are, in
`drivers/gpu/intel_gpu_xelpg_external`:
`smoke_mtl_external_dp_on_pipe_b_beside_lit_panel`,
`smoke_mtl_external_hdmi_on_pipe_b_beside_lit_panel`,
`smoke_mtl_external_no_free_pipe_or_resources_refuse_before_mmio`,
`smoke_mtl_external_failed_activation_repartitions_back`,
`smoke_mtl_external_pm_demand_at_route_port_clock`,
`smoke_mtl_external_route_arm_runs_inside_irq_masked_evasion` and
`smoke_mtl_external_route_presence_has_no_transient_readers`. In
`drivers/gpu/intel_gpu_xelpg_pipes`:
`smoke_xelpg_pipes_dmc_brackets_the_external_crtc`,
`smoke_xelpg_pipes_arm_runs_inside_irq_masked_evasion` and
`smoke_xelpg_pipes_release_of_last_pipe_forgets_state`. In
`drivers/gpu/intel_gpu_xelpg_live`:
`smoke_xelpg_live_panel_arm_runs_inside_irq_masked_evasion`. In
`drivers/gpu/intel_gpu_modeset_xelpg`:
`smoke_mtl_modeset_reports_pipe_a_dmc_around_its_crtc`. The hook-pass smoke
in `drivers/gpu/intel_gpu` now also checks the published pipe and samples the
lock-free readers from inside a pass.

Integration: the join needed one production fix. `mbus_ctl_join_update`
selects the joined pipe when it stays lit without a modeset
(`intel_mbus_joined_pipe`), so the live repartition that gives Pipe A its
whole profile back re-joins MBUS with Pipe A selected. The owned modeset
joins with NONE. `Profile::capture` accepted only NONE, so after any
external route stopped, KMS flips, the cursor and PSR on the panel refused
until the next modeset. The DP, HDMI and failed-activation smokes caught it.
The capture now accepts either select while joined; Linux's MBUS readout
only takes `MBUS_JOIN`. Another pipe's select, a missing hashing mode or an
unjoined MBUS still refuse. `smoke_mtl_resource_profile_accepts_either_joined_mbus_select`
in `drivers/gpu/intel_gpu_cursor` pins both cases.

`ActivateError` carries a `large_enum_variant` allowance: like the existing
`result_large_err` allowances, it hands the owner back by value, once per
activation. These are native models, not physical Intel evidence.

### Shared-GGTT GuC TLB invalidation on GT0 and the media GT

Linux b90c984d invalidates the GGTT TLB of each GuC of the tile after every
GGTT update. This is xe_ggtt.c::xe_ggtt_invalidate, which calls
ggtt_invalidate_gt_tlb on the primary and the media GT. Before this change the
shared arena never invalidated GT0's GuC TLB. It wrote GT1's GUC_TLB_INV_CR
only before media submission, and then relied on the per-context
TLB_INVALIDATION around registration. A range freed and reused outside a
registration could leave a GuC holding a stale translation to freed or reused
memory.

`intel_gpu_ggtt_tlb` now gives the arena one client per GuC. GT0's GuC is a
client of every authorized arena from its construction. The MTL/Arrow media
GuC is a client while it is registered. Every PTE publication or clear is one
generation. While a GuC's CT or submission is off, the arena invalidates it by
MMIO at once, following xe_guc_tlb_inval.c::send_tlb_inval_ggtt. That is
GUC_TLB_INV_CR before Xe2 (MTL, DG2, Gen12 and GT1 at the GSI offset) and
PVC_GUC_TLB_INV_DESC1 then DESC0 on BMG, LNL and PTL, after the VF_CAP_REG
barrier. From `SchedulingReady` the GT's scheduler sends
XE_GUC_ACTION_TLB_INVALIDATION {seqno, MAKE_INVAL_OP(XE_GUC_TLB_INVAL_GUC)} on
fence 0 for the newest generation, ahead of that poll's other H2G. Only the
exact TLB_INVALIDATION_DONE seqno completes it. Seqnos follow
xe_tlb_inval_fence_prep: they start at 1, wrap at 0x100000 and skip 0. They
also skip live per-context stamps, and new context stamps skip the in-flight
seqno, so a 0x7001 cookie never has two owners. The per-context invalidations
themselves are unchanged.

Removal follows ggtt_node_remove: the PTEs are cleared, then the GuCs are
invalidated before the backing is freed. The arena cannot wait, so a cleared
range keeps its frames and stays out of the first-fit free list until every
GuC has invalidated past the clear. A request unanswered for
tlb_inval_timeout_delay (HZ/4 plus twice one second per 4 KiB of H2G CTB,
2.25 s), or a DONE with no in-flight owner, fails the scheduler with `Timeout`
or `Protocol`. The GT is then lost and goes through the normal reset
escalation. Linux signals -ETIME and frees; NARF keeps the ranges retained.
`GuCGt::begin_stop` returns the GuC to MMIO but keeps any CT debt. Only the
proven GuC stop (or the unsafe full-reset release) settles that debt, as
xe_tlb_inval_reset does. It also removes the stopped GuC from the clients, so
the arena never writes a GuC register after its owner may have released the
GT wake. The media owner's registration and unregistration are unchanged.

Other differences from Linux, all fail-closed:
- One request per GuC is in flight. It covers every update published before
  it was sent.
- An insertion's CT invalidation is queued, not waited for. The per-context
  invalidation before registration still waits.
- There is no G2H credit reservation: NARF's CT keeps no G2H credit
  accounting, and at most one request per GuC is outstanding.

Lock order: the runtime's GT mutex, then the GT, scheduler and CT (owned
exclusively, no lock), then the arena's IRQ-safe spin lock, then the frame
allocator. The arena has no CT handle. The scheduler reads the pending
generation and reports a completion through short arena calls, and sends the
H2G between them with no arena lock held. Frees made while the scheduler
handles G2H only record retention. No IRQ handler or timer touches the arena
or the CT.

GT0 behaviour without `narf.intel.media_gt=1` changes on purpose: every
authorized GuC arena now writes GT0's invalidation register on each
publication and clear. The three media fixtures that pinned GT0's
GUC_TLB_INV_CR as unwritten now expect GT0's write. GT1's register behaviour
stays as before, and the CT-mode fixture also checks the held removal.

New fixtures under `drivers/gpu/intel_gpu_ggtt_tlb`:
- Tracker, request and wire checks.
- The real `SharedArena` over a RAM BAR: MMIO on every update for MTL, DG2,
  TGL and BMG, and none on the legacy arena; CT-mode removal blocking first-fit
  reuse until the covering DONE; an unproven stop retaining ranges until the
  reset proof; GT0 and GT1 both covering before release.
- On the GuC model: GT0 MMIO before CT, the CT action and DONE releases,
  verified stop, seqno and context-stamp disjointness through a full kernel
  job, and timeout and stale-DONE retention and loss.

Under `drivers/gpu/intel_gpu_media_gt`,
`smoke_ggtt_tlb_media_gt_ct_invalidation_and_proven_stop` runs GT1 through
MediaGuc. These are native models, not physical Intel evidence. Silicon
confirmation of the GuC-type invalidation round trip on each platform remains.

Review against Linux b90c984d agreed on the following:
- Register selection matches `send_tlb_inval_ggtt`: DESC1 BIT6 then DESC0
  BIT0 for GRAPHICS_VER >= 20, otherwise GUC_TLB_INV_CR BIT0, after
  `xe_ggtt_invalidate`'s VF_CAP_REG read.
- The action encodes as `MAKE_INVAL_OP(XE_GUC_TLB_INVAL_GUC)` = 0x80000003.
- Seqnos match `xe_tlb_inval_fence_prep`.
- Queuing insert invalidations without waiting is sound. In Linux only
  objects flagged `XE_BO_FLAG_GGTT_INVALIDATE` wait on insert, and those are
  the GuC CT, ADS, log, PC, hwconfig, HWSP and the queue-group CGP, which NARF
  allocates before CT, where its MMIO invalidation is synchronous. Linux's
  runtime LRC inserts do not invalidate at all. A reused range can only be
  cached if a GuC touched it before its removal, and removal retention covers
  that. A range never handed to a GuC is not cached by it.
- The scheduler reads the pending generation and reports completion through
  short arena calls, and sends the H2G with no arena lock held.

### Main-GT L3 bank topology entry

GT0's native Xe topology now carries the DRM_XE_TOPO_L3_BANK entry that
xe_query.c::query_gt_topology always reports for a primary GT
(xe_gt_topology_report_l3 holds for every non-media GT) and that Mesa reads
for l3_banks. GtTopology::read samples load_l3_bank_mask's fuses after the EU
fuse, inside both existing stable samples under the same GT wake:
MIRROR_FUSE3 everywhere, plus XEHP_FUSE4 on MTL/Arrow and
MIRROR_L3BANK_ENABLE on PTL. `L3Rule` picks Linux's branch by graphics IP
(inverted bank bits on Gen12 TGL/ADL, eight banks per mslice on DG2, the 12.70
pair rule on MTL/Arrow, the Xe2 mode nibble per node on BMG/LNL, 32 bank bits
per node on PTL) and expands it as gen_l3_mask_from_pattern does into 64 bits.
The 8-byte entry sits between the compute DSS and EU entries. The media GT
now calls the same 12.70 function, with unchanged bytes.

Every NARF-admitted platform reports the entry. The only omission is a PTL
snapshot enabling an L3 node above 1: its pattern would shift past bit 63,
which xe_assert forbids and C leaves undefined, so NARF omits that entry
rather than guess. Linux's i915 topology queries have no L3 field, so the
compatibility path is unchanged.

This intentionally changes the ABI: the PTL native-Xe fixture's reply grows
from 50 to 66 bytes, the MTL media-GT fixture counts four GT0 entries instead
of three, strict mock fuse windows now answer MIRROR_FUSE3 and XEHP_FUSE4, and
the context-seed instability fixture flips MIRROR_FUSE3 only during the seed's
own samples. New `intel_gpu_topology` fixtures check each
branch and the platform mapping
(`smoke_l3_bank_rules_follow_load_l3_bank_mask`), read order and double
sampling (`smoke_gt_topology_samples_l3_fuses_after_eu_fuses`), and exact
query bytes on TGL, ADL-P/S/N, DG2, MTL, BMG, LNL and PTL with fused-off banks
and the PTL omission (`smoke_xe_gt_topology_query_reports_gt0_l3_bank_entry`).
None is physical Intel or Mesa evidence.

Review against Linux b90c984d agreed on the following:
- Every `load_l3_bank_mask` branch matches:
  - the final branch `~MIRROR_FUSE3` 7:0;
  - DG2 0xff per `MEML3_EN_MASK` (3:0) node;
  - 12.70 `GT_L3_EXC_MASK` (`XEHP_FUSE4` 6:4) pairs, four bits per node;
  - Xe2 `XE2_GT_L3_MODE_MASK` (7:4) per `XE2_NODE_ENABLE_MASK` (31:16) node;
  - Xe3 all 32 `XE3_L3BANK_ENABLE` bits per node.
- They expand as `gen_l3_mask_from_pattern` does into the 64-bit
  `xe_l3_bank_mask_t`.
- `query_gt_topology` order is geometry, compute, L3, then EU, GT0 before GT1.
- A PTL node above 1 omits only the L3 entry. Linux has an `xe_assert` there
  and an undefined shift.
- The i915 topology queries are unchanged.

### The panel's KMS services beside a lit external — native fixtures added

This slice closes the five follow-ups of the Pipes B–D join. The sources
are Linux b90c984d: `intel_display.c` (`intel_atomic_commit_tail`,
`hsw_crtc_enable`, `hsw_configure_cpu_transcoder`,
`intel_set_transcoder_timings`, `hsw_set_frame_start_delay`,
`hsw_set_transconf`, `hsw_set_linetime_wm`, `skl_linetime_wm`,
`icl_set_pipe_chicken`, `bdw_set_pipe_misc`, `intel_enable_transcoder`),
`intel_vrr.c::intel_vrr_set_transcoder_timings`, `skl_watermark.c`
(`skl_wm_check_vblank`, `skl_ddb_add_affected_pipes`), `intel_psr.c`
(`intel_psr_pre_plane_update`, `intel_psr_post_plane_update`),
`intel_fbc.c` (`intel_fbc_pre_update`, `__intel_fbc_pre_update`,
`intel_fbc_post_update`), `intel_cdclk.c::bxt_modeset_calc_cdclk`,
`intel_pmdemand.c::intel_pmdemand_atomic_check`, and the register headers
`intel_display_regs.h`.

**Panel KMS with an external lit.** The Pipe B–D owner publishes what it
programmed while any Pipe B–D belongs to it: the state, plus each reserved
pipe's scanout surface. The panel's resource profile first tries the owned
single-pipe layout. Otherwise it proves Pipe A's share of the published
layout against the hardware:

- the panel request of the mode, with every pipe outside the layout off;
- PM demand covering the layout, with the exact QGV value;
- MBUS join and hashing as computed, with the select NONE or an active pipe;
- each active pipe's DBOX, IPC and the DBUF slices;
- every pipe's plane and cursor DDB at exactly its entry.

The published layout only names what to expect. A foreign lit pipe, a moved
DDB entry, a grown panel allocation, a select of an inactive pipe or no
published layout all refuse, and the failed proof publishes an unknown
`wm_level_disabled`. The retained primary owner derives its linear/X and
Tile4 images from whichever layout is proved at each use. Cursor, primary,
Tile4 and XR30 therefore use Pipe A's actual allocation. The KMS takeover
inventory admits exactly the route's own Pipe B–D primary surface (outside
the GEM arena) and nothing else. A KMS tiling change is modeled as
`State::retile`: only the primary watermarks change, and a tiling that
would move a DDB entry is refused. The Pipe B–D owner computes Pipe A from
the linear baseline the KMS owner programs and retiles it to the scanned-out
tiling, and it retiles before each transition. A panel flipped to Tile4
therefore no longer looks diverged to the live repartition. A lit pipe whose
cursor watermarks are programmed while the cursor sits off screen keeps them.

**The external pass.** The runtime MTL pass used `legacy_drain`. That
disabled PSR and FBC on every pass and left the KMS owner blocked, so the
desktop lost flips after the first pass. Probe-time MTL events also
suspended the owner. `Device::external_pass` now holds the owner without
blocking it. Linux adds Pipe A to a commit that moves its DDB
(`skl_ddb_add_affected_pipes`), so the two are serialized; the pass does the
same. It never waits on another task: a busy owner or an unlatched primary
flip skips the pass before its hotplug poll. A panel DSB stream left in
flight by a dropped cursor or color future is retired first, bounded, as a
Linux commit waits for the previous commit's DSB; the owner's next call
completes its bookkeeping. Around each event:

- `pre_update` deactivates FBC (`intel_fbc_pre_update`, then Display WA
  #1198's vblank when FBC was active). NARF always takes the deactivate
  branch because the live transaction requires FBC off; Linux would flip-nuke
  an unchanged plane. For Pipe A without a modeset,
  `intel_psr_pre_plane_update` keeps PSR enabled and sets Wa_14015648006
  when Pipe A's `wm_level_disabled` is true. PSR then exits and waits for
  idle, as the pipe update does.
- `post_update` waits for a Pipe-A frame boundary, because Linux runs its
  post-plane updates after flip_done. It then re-proves Pipe A's share of
  whatever layout now holds. Only a proved layout clears Wa_14015648006 when
  `wm_level_disabled` is false and re-activates the FBC it deactivated, on
  the same CFB. PSR re-arms from idle when the pass ends. An unproved layout
  disables PSR (its next qualification re-proves the watermarks) and leaves
  FBC off until the next latch.

The suspend and reset retirement of a live route uses the same bracket,
except after a GT reset, where the owner's loss-tolerant recovery disables
FBC and PSR. `wm_level_disabled` depends only on Pipe A's planes and timing,
as `skl_wm_check_vblank` computes it per crtc, so the multi-pipe proof
publishes the same value. PSR therefore enables beside a lit external.

**Pipes B–D crtc registers.** `Pipes::program_timings` now follows
`hsw_crtc_enable` for display 14, with the pipe off:

- `PIPE_MISC` = `BPC_8 | PIXEL_ROUNDING_TRUNC | HDR_MODE_PRECISION` after
  the source size (`is_hdr_mode` holds with only the primary active);
- then `TRANS_SET_CONTEXT_LATENCY` 0 and `TRANS_VSYNCSHIFT` 0, the timings,
  `TRANS_VRR_CTL` 0 without VRR, `TRANS_MULT` 0, the display-14
  `CHICKEN_TRANS` frame-start delay field 0, and `TRANSCONF` configured
  progressive and still disabled;
- after the RGB bypass, `WM_LINETIME` = `skl_linetime_wm` (`DIV_ROUND_UP`
  of htotal × 8000 by the pixel rate, capped at 0x1ff; no IPS line time on
  display 14);
- `PIPE_CHICKEN` |= alpha bypass, pixel rounding passthrough and underrun
  recovery disable.

`Pipes::enable` sets `DP_FEC_BS_JITTER_WA` and clears
`DP_DSC_INSERT_SF_AT_EOL_WA` in `CHICKEN_TRANS` before `TRANSCONF` enables,
as `intel_enable_transcoder` does. Chicken registers are read-modify-written.
Audited and not applicable: DSC and the uncompressed joiner (refused), the
pipe scaler (`skl_pfit_enable` only with a panel fitter), M2/N2 (not on
display 14), the IPS line time and HSW-only workarounds. One divergence
remains: `TRANS_VBLANK` keeps its start field at vactive−1, while Linux
writes 0 on display 13+ because the hardware ignores the field.

**After the last release.** Releasing the last Pipe B–D with no lit panel
now runs the post-plane half of the all-off commit (`settle_all_off`). With
every pipe, plane, cursor, DSB and FBC proved off, it clears every plane and
cursor WM/DDB and powers the DBUF down to S1. It lowers CDCLK to
`bxt_calc_cdclk(force_min_cdclk)` (172.8 MHz), then lowers the PM demand to
the no-pipe request: S1, no pipe, port clock or PHY, the clock's voltage
level, and the QGV point chosen for no plane. A lit pipe refuses before any
write. A failure re-requests the original demand, so the demand never
under-covers the clock. The step is best effort.

Remaining: one external route at a time. The pass skips while a cancelled
panel flip is unlatched, until the owner's next call completes it. The MBUS
join is left as it was after the last release; the next all-off commit
rewrites it. Physical Intel acceptance is open.

Fixtures:

- `drivers/gpu/intel_gpu_xelpg_external`:
  `smoke_mtl_panel_profile_proves_its_share_beside_external`.
- `drivers/gpu/intel_gpu_xelpg_pipes`:
  `smoke_xelpg_pipes_publish_layout_and_follow_a_tile4_panel_flip`,
  `smoke_xelpg_pipes_crtc_enable_programs_linetime_chicken_and_frame_start`
  and `smoke_xelpg_pipes_last_release_lowers_cdclk_and_pm_demand`.
- `drivers/gpu/intel_gpu_kms` (x86_64):
  `smoke_kms_mtl_panel_flip_cursor_and_color_beside_lit_external`,
  `smoke_kms_mtl_cursor_refuses_diverged_multi_pipe_layout`,
  `smoke_kms_mtl_psr_enables_beside_external_and_brackets_repartitions`,
  `smoke_kms_mtl_external_pass_deactivates_and_reevaluates_fbc` and
  `smoke_kms_mtl_external_pass_idles_in_flight_dsb_before_repartition`.

Changed fixtures:

- `smoke_mtl_external_dp_on_pipe_b_beside_lit_panel` asserted that the panel
  profile refused beside the external. It now asserts that the profile holds
  Pipe A's half of the DBUF.
- `smoke_xelpg_pipes_release_of_last_pipe_forgets_state` asserted that the
  release wrote nothing. It now asserts that the release writes only the
  all-off settle.
- The hook-pass smoke also counts the new post-event hook.

The KMS mock gained a register-read tick for synchronous waiters, and the
PSR KMS fixture helpers are shared with the new module.

The integration made two follow-up changes, plus a Clippy fix that gates the
KMS mock's x86_64-only read tick on aarch64.

The first is a regression fixture. No J3 fixture drove the runtime wrapper
itself; the multi-pipe smokes call `external_pass` directly. The wrapper's
owner hold is now `crate::intel_gpu::mtl_runtime_pass`, which is generic
over the KMS platform and called by `service_mtl_external_for_bar`.
`smoke_kms_mtl_runtime_pass_leaves_the_panel_owner_open` (in
`drivers/gpu/intel_gpu_kms`) runs passes with and without an event through
it, beside a lit external, and then requires the panel's session and cursor.
With the old `legacy_drain` body restored in the helper, it fails with "the
runtime pass left the panel's KMS owner blocked". The regression it pins came
in with the MTL runtime wiring (dd1242b9b).

The second sets `PIPE_MISC_HDR_MODE_PRECISION`. `bdw_set_pipe_misc` sets
bit 23 on display 11 and later whenever `is_hdr_mode` holds, which is
always true for a primary-only Pipe B–D. The Pipe A paths (MTL owned modeset
and Gen12) never write `PIPE_MISC` and are unchanged.

Review against Linux b90c984d agreed on the following:
- The crtc order follows `hsw_crtc_enable` and
  `hsw_configure_cpu_transcoder`. `intel_enable_transcoder` sets the display-14
  `CHICKEN_TRANS` bits: `DP_FEC_BS_JITTER_WA` on and
  `DP_DSC_INSERT_SF_AT_EOL_WA` off.
- `skl_linetime_wm` is `DIV_ROUND_UP(htotal * 8000, pixel_rate)`, capped at
  0x1ff.
- WA #1198 waits a vblank only when FBC was active (`fbc->activated`).
- The all-off settle runs in Linux's post-plane order: DBUF to S1, then CDCLK
  to `bxt_calc_cdclk(0)`, then the no-pipe PM demand, as
  `intel_dbuf_post_plane_update`, `intel_set_cdclk_post_plane_update` and
  `intel_pmdemand_post_plane_update` run.
- Deliberate divergence: FBC is always deactivated around a repartition.
  Linux keeps it when `intel_fbc_can_flip_nuke` allows.

### MTL/Arrow media GT power: GuC SLPC, GuC RC6 and powergating

With `narf.intel.media_gt=1`, GT1 now gets power management the way Linux
b90c984d runs it for every GT. Before this, GT1 had no frequency management
and no RC6, so turning the option on cost power. Without the option nothing
changes: no media owner exists, GT0's SLPC start and stop are unchanged, and
GT0 never reads a media frequency register.

`intel_gpu_slpc` is parameterized by GuC role rather than copied. For the
media GuC, `Limits::read_media` follows xe_guc_pc.c's mtl_* helpers for a
media GT. RP0 and RPn come from MTL_MEDIAP_STATE_CAP (0x138020, bits 8:0 and
24:16) and RPe from MTL_MPE_FREQUENCY (0x13802c, bits 8:0), each decoded as
DIV_ROUND_CLOSEST(raw * 50, 3). Both registers lie above
MEDIA_GT_GSI_LENGTH, so GT1's window reads them at their absolute offsets.
Two equal samples are required, and RPn must be nonzero with RPn <= RPe <=
RP0. No conservative bound applies to media 13.00: Wa_22019338487 is
MEDIA_VERSION(2000) only and Wa_14022085890 is BMG G21 only.

The media start follows xe_guc_pc_start on the media GuC. It allocates and
zeroes the 8 KiB shared data, sends SLPC_EVENT_RESET and waits up to 1005 ms
for RUNNING. It then queries the task state. pc_adjust_freq_bounds lowers
only a firmware default above RP0: the maximum first, then the minimum
through IGNORE_EFFICIENT_FREQUENCY and the minimum, as pc_set_min_freq does.
Bounds left as firmware set them must lie within the fused limits; programmed
bounds are confirmed by a readback. pc_init_pcode_freq does nothing here,
because mtl_desc has no LLC. The start ends with
SETUP_PC_GUCRC(GUCRC_FIRMWARE_CONTROL), which hands media C6 to firmware,
SLPC_PARAM_STRATEGIES = SLPC_OPTIMIZED_STRATEGY_COMPUTE and the Base power
profile. Before SLPC, GT1 enables powergating as xe_gt_idle_enable_pg does
for a media GT: POWERGATE_ENABLE at its GSI copy (0x38a210) gets
MEDIA_POWERGATE_ENABLE plus both VDN powergate bits of each present VCS.
There is no render bit and no media-sampler bit, the hysteresis writes are
skipped with GuC PC, and Wa_14020316580 (media 13.01) does not apply.

`MediaGuc` runs this after the default LRCs and the per-engine probes, and
before HuC authentication, matching xe_uc_load_hw's order. GT1 publishes only
once SLPC is RUNNING. The runtime logs the confirmed limits and range once at
publication. As on GT0, the shared data is allocated after CT enablement and
its insert invalidation is queued; the shared-GGTT review above shows that
is sound for a range no GuC has cached.

Every media stop hands power back to the host before resetting the media
GuC: recovery, GT0 park, system suspend and GT0 fault cleanup all use it.
With GT1's wake held, the stop sends SETUP_PC_GUCRC(GUCRC_HOST_CONTROL) if
firmware control was handed over, then writes RC_CONTROL = 0 and RC_STATE = 0
at 0x38a090/0x38a094 and POWERGATE_ENABLE = 0. These are
xe_guc_pc_gucrc_disable, xe_gt_idle_disable_c6 and xe_gt_idle_disable_pg.
Linux runs the first two before a GT reset and powergate disable at suspend.
NARF has one verified stop for all of these cases, so it always runs all
three, and the next media GuC enables them again. Linux's xe_pm_resume also
disables C6 early on resume. NARF needs no separate resume step, because GT1
is always handed back to the host before it leaves D0.

Failure policy follows the source. xe_uc_load_hw returns a xe_guc_pc_start
error, which fails probe or wedges the device after a reset. NARF therefore
never publishes GT1 without SLPC. Unreadable fuses, global ERROR, no RUNNING
within the bound, a refused or unacknowledged bound or profile, and a lost
transport all stop GT1 with its verified stop. GT0 is unaffected, and the
runtime's one media recovery per GT0 incarnation may retry once. A refused
compute strategy is not a failure, because xe_guc_pc_start overwrites that
result with the profile's. If SLPC fails after publication, its confirmed
status disappears and the engines keep running, as on GT0; Linux has no such
monitor and only returns later set_param errors to their caller.

Differences from Linux, all fail-closed:
- Parameter requests are acknowledged REQUESTs; Linux sends them as fast
  requests.
- NARF adds a confirming readback after programmed bounds and checks the RPe
  ordering.

No userspace interface is added. Linux exposes per-GT
`device/tile0/gt1/freq0/` (act, cur, rp0, rpa, rpe, rpn, min, max and
power_profile) and `gtidle/` (gt1-mc, MC6 residency from 0x138048). NARF
exposes GT0's SLPC only through i915-named card attributes, not that Xe
tree, so it has no GT0 counterpart to mirror. GT1's frequency and idle sysfs
stay absent. The earlier HuC checkpoint's remark that GT1 runs no SLPC is
superseded.

New fixtures under `drivers/gpu/intel_gpu_media_gt`:
- `smoke_media_gt_slpc_limits_decode_gt1_fuses_only` covers the decode, its
  refusals, and the per-role register selection and powergate values.
- `smoke_media_gt_slpc_start_bounds_profile_and_rc6_on_media_guc` covers the
  exact H2G sequence and confirmed status with GT0 decoy fuses, publication
  only after RUNNING, the C6/powergate handoff before the GuC reset on stop
  and in `media::retire`, and the recovery restart.
- `smoke_media_gt_slpc_failures_stop_gt1_and_disable_c6` covers the global
  ERROR, timeout, refused-bound and unreadable-fuse stops, the ignored
  strategy refusal, and SLPC loss after publication with a user job still
  retiring.
- `smoke_media_gt_power_absent_leaves_gt0_slpc_and_stop_unchanged` pins GT0's
  sequence and stop, and the MMIO-free retirement without a media owner.

The shared GuC model now records SLPC traffic. It accepts the strategy and
HOST_CONTROL only from a registered media GuC, and the media model has GT1
frequency fuses. Every existing GT1 fixture now runs the SLPC start before
publication. These are native models, not physical Intel evidence.

Integration: this unit applied on top of the L3, shared-GGTT and J3 units
without a code conflict or a fix. Every existing `intel_gpu_media_gt` fixture
passes with the SLPC start, and the 21 GT0 `intel_gpu_slpc` fixtures are
unchanged and pass.

Review against Linux b90c984d agreed on the following:
- The start follows `xe_guc_pc_start`: RESET, then RUNNING within the reset
  timeout, then `pc_adjust_freq_bounds` on the first task-state query (max
  then min, lowered only above RP0), then `SETUP_PC_GUCRC(FIRMWARE_CONTROL)`,
  the compute strategy and the cached power profile. A refused strategy is
  overwritten by the profile's result, as there.
- The media fuses match `mtl_init_fused_rp_values` and `mtl_get_rpe_freq`
  for a media GT: RP0 is `MTL_MEDIAP_STATE_CAP` (0x138020) bits 8:0, RPn is
  bits 24:16, and RPe is `MTL_MPE_FREQUENCY` (0x13802c) bits 8:0. Both are
  absolute addresses above the GSI length.
- `POWERGATE_ENABLE` (0x38a210) = 0x19a for VCS0/VCS2/VECS0 matches
  `xe_gt_idle_enable_pg`: MEDIA plus VDN HCP/MFX for VCS0 and VCS2, no RENDER
  on a media GT, and Wa_14020316580 is media 13.01 only.
- The stop clears `RC_CONTROL` and `RC_STATE` as `xe_gt_idle_disable_c6`
  does, after `GUCRC_HOST_CONTROL`.
- Disabling powergating at every stop, where Linux does it only at suspend,
  is harmless. It only keeps the wells powered until the next owner
  re-enables gating, and every stop is followed by a GuC reset or a park.
- A failed SLPC start stops GT1 unpublished, as `xe_uc_load_hw` fails the
  uC load.

### Display-14 DSC, the panel-fitter model and TRANS_VBLANK — native fixtures added

This slice adds Display Stream Compression to the Meteor Lake display,
models the pipe scaler, and fixes one register value. Sources are Linux
b90c984d: `intel_dp.c` (`intel_dp_compute_link_config`,
`intel_dp_compute_link_config_wide`, `intel_dp_compute_config_limits`,
`intel_dp_dsc_compute_config`, `intel_dp_dsc_get_slice_count`,
`intel_dp_dsc_compute_params`, `intel_edp_init_dpcd`,
`intel_dp_get_dsc_sink_cap`), `intel_vdsc.c`, `intel_vdsc_regs.h`,
`intel_qp_tables.c`, `drm_dsc_helper.c`, `drm_dp_helper.c`, `intel_ddi.c`
(`mtl_ddi_pre_enable_dp`, `intel_ddi_post_disable`, the FEC helpers),
`intel_hdmi.c::hsw_write_infoframe`, `intel_display.c`
(`hsw_crtc_enable`, `intel_link_compute_m_n`,
`intel_set_transcoder_timings`), `intel_cdclk.c::intel_crtc_min_cdclk`,
`skl_prefill.c`, `skl_scaler.c`, `intel_pfit.c` and `drm_rect.c`.

**The decision.** NARF's pipe runs at 8 bpc, so the decision is Linux's
with `max bpc` 8. When 24 bpp fits the link, the stream stays uncompressed.
When only 18 bpp fits, Linux would drive 6 bpc, which this pipe does not
offer, so the modeset refuses. Otherwise the stream is compressed when
the sink decompresses. On eDP the plan takes the panel's maximum link and
its maximum bpp and slice count. On DP it takes the highest compressed
bpp that fits with FEC's overhead, then the lowest rate and lane count,
and Linux's slice count for the sink's throughput and slice width. The
rate-control parameters follow `calculate_rc_params` with the 8 bpc
tables, then the shared `drm_dsc_compute_rc_parameters`. Refusals are
typed `DscRefusal`s: no DSC or RGB, the VBT's `edp.dsc_disable`, a VBT
that picks its panel by PnP ID, no FEC on DP, no bpp range, link or slice
count, more than four slices (two engines, no joiner), invalid slice
dimensions, line buffer or rate control, an intermediate maximum rate, a
branch device, and an eDP stream its maximum link cannot carry (Linux
does not check that case). The DRM helpers Intel shares with AMD moved
into the ungated `drm_dsc` module; `amdgpu_dsc` re-exports them.

**The eDP panel.** The Pipe A modeset reads the panel's receiver caps,
eDP revision, eDP 1.4 rate table and DSC caps before it stops anything,
so a refusal leaves the panel as it was. A panel that is not DSC capable
keeps the existing sequence. A compressed modeset programs the PHY PLL
and trains at the plan's link, writes `DP_SET_POWER` D0 and
`DP_DSC_ENABLE` before training, and refuses a training fallback,
because the configuration was computed for that link. After the normal
pattern it writes the PPS SDP, Pipe A's VDSC engines (`ICL_DSC0/1` at
0x78000, since every display 12+ pipe owns its engines), the compressed
M/N with TU 64, and the display-14 `CHICKEN_TRANS` bits, then enables
the transcoder. A panel firmware left compressing is torn down in Linux's
order: sink decompression off, the transcoder off, then `DSS_CTL1/2` and
the PPS SDP enable cleared.

**External DP.** A DPCD 1.4 sink reports its DSC and FEC capabilities at
probe. A compressed route writes `DP_DSC_ENABLE` and
`DP_FEC_CONFIGURATION` before training, enables FEC in `DP_TP_CTL` and
writes the PPS SDP after the normal pattern, then programs the route
pipe's engines and the compressed M/N. After the transcoder enable it
waits for the FEC status as Linux does, and like Linux only notes a
timeout. The stop reverses the sequence. PM demand uses the plan's link
rate. A sink that does not decompress keeps the `OverBudget` refusal.

**Resources.** A compressing pipe adds `intel_vdsc_min_cdclk` to the
CDCLK minimum and 1.5 lines of DSC prefill to the watermark vblank check.
`PipeRequest` and `ExternalPipe` carry the term. The owned modeset passes
the planned term. Every later proof of the panel layout (the KMS profile
capture, the retained primary, the Pipe B–D adoption) reads the term back
from Pipe A's engines, as `intel_dsc_get_config` does. The inherited
layout raises CDCLK to the VDSC minimum too.

**The panel fitter.** `intel_gpu_xelpg_scaler` models
`pch_panel_fitting`'s window (centered, aspect and fullscreen), scaler
admission with display 14's limits, `skl_pfit_enable`'s register image,
the nearest-neighbour coefficient table, `skl_scaler_disable` and the
scaler prefill lines. Downscaling is refused, because it raises the pipe
pixel rate and with it CDCLK and the watermarks. The model has no
production caller. A fitted Pipe A also needs the KMS owners to learn the
pipe source size, since they size the primary from the transcoder timing.

**TRANS_VBLANK.** Display 13+ writes 0 to the start field, because the
hardware ignores it there. The Pipe A modeset and the Pipes B–D owner now
do the same. The display-14 DSB timing proof compares only the end field;
the Gen12 proof is unchanged.

Remaining: the joiner, more than four slices, YCbCr DSC and fractional-bpp
limits beyond the sink's increment, UHBR DSC, MST DSC and the DSC throughput
quirk of branch devices (branches refuse). 6 bpc output, `DP_LINK_RATE_SET`
training, the VBT's `edp.bpp` clamp and display 13's `TRANS_VBLANK` are the
next section. Physical Intel acceptance is open.

Fixtures:

- `drivers/gpu/drm_dsc`: `smoke_drm_dsc_rc_buf_thresh_and_pps_sdp_header`.
- `drivers/gpu/intel_gpu_xelpg_dsc`:
  `smoke_xelpg_dsc_dpcd_accessors_follow_drm_dp_helper`,
  `smoke_xelpg_dsc_edp_oled_config_matches_linux`,
  `smoke_xelpg_dsc_edp_single_slice_dsc11_matches_linux`,
  `smoke_xelpg_dsc_dp_fec_config_matches_linux`,
  `smoke_xelpg_dsc_edp_decision_and_refusals`,
  `smoke_xelpg_dsc_dp_decision_and_refusals`,
  `smoke_xelpg_dsc_engine_registers_per_pipe`,
  `smoke_xelpg_dsc_program_enable_disable_sdp_mn_and_fec` and
  `smoke_xelpg_dsc_sink_caps_decompression_and_fec_ready`. Their
  rate-control, register, SDP, M/N and CDCLK values were produced by
  Linux's own helper code compiled outside the kernel.
- `drivers/gpu/intel_gpu_modeset_xelpg`:
  `smoke_mtl_edp_dsc_modeset_programs_vdsc_pps_and_sink`,
  `smoke_mtl_edp_dsc_refusals_precede_every_write`,
  `smoke_mtl_modeset_tears_down_firmware_dsc_in_linux_order` and
  `smoke_mtl_modeset_trans_vblank_start_field_is_zero`.
- `drivers/gpu/intel_gpu_xelpg_external`:
  `smoke_mtl_external_dp_dsc_with_fec_lights_and_stops` and
  `smoke_mtl_external_dp_dsc_refusals_precede_programming`.
- `drivers/gpu/intel_gpu_xelpg_resources`:
  `smoke_xelpg_resources_dsc_pipe_adds_vdsc_cdclk_and_prefill`;
  `drivers/gpu/intel_gpu_xelpg_wm`:
  `smoke_xelpg_wm_dsc_prefill_adds_one_and_a_half_lines`.
- `drivers/gpu/intel_gpu_xelpg_scaler`:
  `smoke_xelpg_scaler_panel_fit_windows_follow_pch_panel_fitting`,
  `smoke_xelpg_scaler_admission_scales_and_refusals`,
  `smoke_xelpg_scaler_pfit_registers_and_nearest_coefficients` and
  `smoke_xelpg_scaler_prefill_lines`.
- `drivers/gpu/intel_gpu_xelpg_pipes`:
  `smoke_xelpg_pipes_trans_vblank_start_field_is_zero_on_display14`;
  `drivers/gpu/intel_gpu_dsb`:
  `smoke_dsb_display14_timing_proves_vblank_end_only`.

Test fixtures that build `PipeRequest` or `ExternalPipe` literals gain
`dsc: None`. `MtlFake` logs its native DPCD writes, and the `ExtFake` sink
models the DSC and FEC DPCD registers.

Integration: the code applied cleanly over the J3 fix-ups. The Pipes B–D
`PIPE_MISC` with HDR mode precision, the runtime-pass helper and the x86_64
read tick all survive. One Clippy fix was needed: the panel-fitter centring
now uses `div_ceil(2)`, which is the same value. Targeted release runs passed
627 tests with no failures, in two selections:
- 168 tests: `drm_dsc`, `intel_gpu_xelpg_dsc`, `intel_gpu_xelpg_scaler`,
  `intel_gpu_modeset_xelpg` (including the fail-closed fixtures),
  `intel_gpu_xelpg_external`, `intel_gpu_xelpg_resources`, `intel_gpu_xelpg_wm`,
  `intel_gpu_xelpg_pipes`, `intel_gpu_xelpg_hdmi`, `intel_gpu_xelpg_live`,
  `intel_gpu_dsb`, `intel_gpu_display_resources` and `intel_gpu_cursor`.
- 459 tests: `intel_gpu_vbt`, `intel_gpu_kms`, `intel_gpu_psr`, `intel_gpu_fbc`,
  `intel_gpu_pipes` and `intel_gpu_modeset`, plus the AMD prefixes that use the
  moved helpers: `dsc`, `dcn30-dsc`, `dcn401-frl-link`, `dcn401-dsc-link`,
  `dcn401-otg`, `dcn401-opp`, `dcn401-mst-audio`, `navi48-mst`,
  `navi48-modeset` and `amdgpu/navi48`.
All prefixes are under `drivers/gpu/`.

The `drm_dsc` move leaves AMD byte-identical. With comments and visibility
stripped, the code removed from `amdgpu_dsc.rs` is the moved code; the
module adds only the Intel-side `set_rc_buf_thresh` and the PPS SDP header.

Review against Linux b90c984d agreed on the following:
- `intel_vdsc_min_cdclk` without a joiner is
  `DIV_ROUND_UP(pixel_rate * (htotal + 14 * slices) / htotal, instances)`.
- `intel_vdsc_prefill_lines` is 0x18000 (1.5 lines).
- The external DP order follows `mtl_ddi_pre_enable_dp`: sink decompression,
  then `FEC_READY` (with the detected flags cleared), then training, then
  `intel_ddi_enable_fec`, then the PPS SDP. The FEC status wait only logs a
  timeout, as in Linux.
- One fail-closed divergence remains: a failed `DP_FEC_CONFIGURATION` or
  `DP_FEC_STATUS` AUX write refuses the route. Linux only logs it.

### GT runtime power: display wakerefs, integrated autosuspend and D3cold — native fixtures added

The sources are Linux b90c984d: `xe_pm.c` (`xe_pm_runtime_init`,
`xe_pm_runtime_suspend`, `xe_pm_runtime_resume`,
`xe_pm_pci_d3cold_capable`, `xe_pm_d3cold_allowed_toggle`,
`vram_threshold_value`), `xe_pci.c` (the runtime suspend, resume and idle
callbacks), `display/xe_display.c` (the runtime display PM hooks),
`display/xe_display_rpm.c`, `intel_display_power.c`
(`intel_display_power_get`, `__intel_display_power_put_async`),
`intel_hotplug.c::i915_hpd_poll_init_work`, `drm_probe_helper.c`
(`DRM_OUTPUT_POLL_PERIOD`), `xe_bo.c` (`mem_type_is_vram`,
`__xe_bo_cpu_fault`, `xe_bo_cpu_fault`,
`xe_bo_runtime_pm_release_mmap_offset`) and `pci.c` (`pci_pme_capable`,
`pci_pr3_present`).

**Which owners take part.** Linux allows runtime PM on every non-VF
function and lets wakerefs decide. `display_rpm::profile` now admits
integrated MTL/Arrow and Gen12 owners with an owned display, beside the
display-less discrete functions. Those owners arm the same 1000 ms
autosuspend and accept the sysfs `auto` and delay requests. LNL/PTL stay
refused: every cold start needs a client-free driver FLR, so no parked user
epoch could continue. Small-BAR BMG stays D0-only.

**Display wakerefs.** In Linux each held display power domain is a runtime-PM
reference, and a lit pipe holds its crtc domains from before its enable to
after its disable. Here, every pipe reported lit holds one usage reference on
the function's runtime-PM device. The reports come from
`pipe_lit_for_bar` and `pipe_dark_for_bar`: KMS install reports the owned
Pipe A, the MTL modeset reports Pipe A around its own disable and enable, and
the Pipe B–D owner reports each external pipe. A lit panel therefore keeps
the function active, matching Linux, and the RPM core never even calls the
park. On display 14 every `DC_off` reference and the 17 ms DC re-entry task
also hold a reference, as Linux's async put does. They are taken only while
the function is runtime-active. A display conversation that starts while the
function is suspending or suspended fails closed before any register access.
Gen12 has no `DC_off` service and no dark report, so its Pipe A wakeref lasts
for the card's lifetime.

**Park and resume.** `display_rpm::park_refusal` re-reads every display hold
under the GT mutex: lit pipes, `DC_off` references, a pending DC re-entry, a
live external route and in-flight KMS work. CPU mappings of system-memory
objects are never an input. Linux revokes CPU mmaps only for VRAM objects,
on its `vram_userfault` list, and system pages stay valid across D3hot. So
an integrated function needs no revocation, and none is done. The display
side follows the Linux D3hot path:

- Linux keeps the DMC program and the DC target across D3hot. The park marks
  the loaded program, and the first publication after the resume verifies
  it under a Load reference before DC5/DC6 is trusted again. A lost program
  is reloaded in that same pass, and the lit pipes' DMC is re-enabled.
- `intel_hpd_poll_enable` becomes the card worker's hotplug policy. While
  the function is runtime-suspended, no per-iteration pass runs. Every 10 s
  one polled detect takes a runtime-PM reference, which resumes the
  function. The reference is held until the restarted GT settles, so the
  following autosuspend sees a running GT.
- The GT restart reloads GuC, re-establishes SLPC and GuC-controlled RC6,
  and replays the confirmed SLPC policy. NARF has no display interrupt, so
  there is no HPD interrupt to re-arm. The KMS owner re-proves its retained
  resource image, including IPC, on its next use.

System-sleep preparation of these owners first takes a runtime-PM reference,
as `pci_pm_suspend` resumes a runtime-suspended function. It holds that
reference until resume.

**Live VRAM mappings: blocked on the memory layer.** Discrete owners still
refuse the park while any VRAM is allocated. Linux zaps the user PTEs of
CPU-faulted VRAM objects (`drm_vma_node_unmap`) and refaults them through
`xe_bo_cpu_fault` under a runtime-PM reference. NARF's Intel mmap installs
eager device-frame backings. The only revocation primitive,
`narf_filesystem::mmap_relocation::relocate`, freezes and swaps frames
synchronously. `unmap_mapping_range` only zaps suffixes of fault-backed file
mappings. Two APIs are needed in `userspace/src/mapped_file.rs` and
`narf_memory::address_space`, which are TCB:

- a revoke operation over a device-frame set that invalidates every user PTE
  and fork alias, keeps the VMAs, and completes the TLB shootdown before it
  returns;
- a per-mapping refault hook that may await the driver's runtime resume and
  then re-installs the same frame.

They were not added here.

**D3cold.** `d3cold::evaluate` gives a typed refusal, and every park logs
it with the `xe_pm_d3cold_allowed_toggle` result. An integrated endpoint has
no root port. A discrete function lacks three things:

- read authority over its root port's PM capability, for PME from D3cold;
- an ACPI companion lookup that evaluates `_PR3`;
- a `PciPlatformPm` provider that turns those power resources off and on.

The runtime-PM node is therefore still registered without a platform
provider, and the PCI layer stops at D3hot. The VRAM threshold (300 MiB,
rounded up per MiB) is implemented and tested, but no production function
reaches it.

**What remains.** The display-14 panel-off producer is "Display-14 panel
off and on" below (atomic `ACTIVE=0`, `SETCRTC` off, `FBIOBLANK`); there is
no connector DPMS property. Once a producer reports the pipe dark, the hooks
above park the function. A Gen12 producer must first give its display
conversations wakerefs, and must park the PWM backlight. D3cold with
eviction and the full restore path, and additional flush consumers, remain
open. Linux's DMI quirk for BMG on NUC13RNG is not modelled, since
D3cold is never capable here.

Native fixtures:

- `drivers/gpu/intel_gpu_power`:
  `smoke_display_rpm_lit_panel_keeps_d0_and_dark_panel_autosuspends`,
  `smoke_display_rpm_wakeref_races_with_suspend_fail_closed`,
  `smoke_display_rpm_bind_counts_lit_pipes_and_rebind_returns_refs`,
  `smoke_display_rpm_park_admission_holds_and_system_memory_mappings`,
  `smoke_display_rpm_profiles_admit_integrated_displays_only`,
  `smoke_display_rpm_hpd_poll_waits_one_period_per_detect`,
  `smoke_d3cold_capability_refusals_follow_xe_pm_order` and
  `smoke_d3cold_vram_threshold_rounds_up_and_refuses_at_limit`.
- `drivers/gpu/intel_gpu_dc_states`:
  `smoke_dc_states_runtime_d3hot_keeps_program_and_reverifies_on_resume`.

The fixtures drive the real runtime-PM core and PCI layer over a model
config space and a fake clock. The GT owner's own park and unpark, the
polled detect and the system-sleep reference are wired but run only on
hardware.

Review against Linux b90c984d agreed on the following:
- `xe_pm_pci_d3cold_capable` checks the root port, then PME from D3cold, then
  `_PR3`, in Linux's order.
- `xe_pm_d3cold_allowed_toggle` rounds VRAM use up per MiB and allows D3cold
  only below the 300 MiB `DEFAULT_VRAM_THRESHOLD`.
- `DRM_OUTPUT_POLL_PERIOD` is 10 s.
- `pipe_lit` takes `get_noresume` only for a newly lit pipe, and `pipe_dark`
  puts with autosuspend only for a pipe that was lit.
- Display-14 `DC_off` references take a wakeref only while the function is
  runtime-active, and fail closed before MMIO otherwise.
- The owned modeset holds `DcUser::Modeset` around its crtc dark-then-lit
  window, so the panel's wakeref never reaches zero inside a modeset.

Hardware-test caveat: the `modeset_xelpg` fixtures build `XeLpgModeset` with
the default `ServicePipeDmc` sink. On real MTL hardware running kernel tests,
they reach the production DC service and now also move the panel's display
wakeref. QEMU is unaffected.

### MTL GSC worker, Wa_14015076503 on the media GuC and the PXP refusals

`narf.intel.gsc=1` is a new default-off option with the shared pre-`--`
grammar. It is admitted only together with `narf.intel.media_gt=1`: Linux
keeps the GSC on the media GT (xe_gsc.c::xe_gsc_init) and makes it
separately optional through `gsc_firmware_path`.

With the option, the media GuC's verified stop honours Wa_14015076503
(xe_gsc.c::xe_gsc_wa_14015076503, MEDIA_VERSION(1300)) as
xe_gt.c::do_gt_reset does. When HECI1_FWSTS1 reports INIT_COMPLETE, the stop
sets HECI_H_GS1 ER_PREP and raises the HECI2 interrupt (IG) with the CSR reset
bit cleared. It waits 200 ms, writes GRDOM_FULL and clears ER_PREP once the
reset self-clears; a failed reset still clears it. The media GT recovery owner
already applied the same bracket, so with the option scheduling is admitted
beside loaded GSC firmware. This is the only place the deviation is dropped.
Without the option both refusals stay exactly as before: scheduling is EBUSY
while GSC firmware is loaded, and a load that appears later keeps the owner
retained at stop.

`intel_gpu_gt::media::gsc::load` ports Linux's GSC worker. It is generic over
the three things only the platform can supply: the GSC kernel queue on GSCCS0,
the 4 MiB GSC private object and the CSME end of the GSC proxy. It covers:
- xe_gsc_init and xe_gsc_init_post_hwconfig with the xe_uc_fw status machine.
- xe_gsc_load_start: a GSC that survived a GT reset or D3hot is only
  re-classified (TRANSFERRED, or RUNNING with PROXY_STATE_NORMAL), and an error
  state never reloads.
- gsc_upload: EEXIST for a loaded GSC, which gsc_work records as RUNNING;
  memcpy_fw into the private object with the tail zeroed; GSC_FW_LOAD with an
  HZ fence wait (ETIME); INIT_COMPLETE within 500 ms (ETIMEDOUT).
- query_compatibility_version (MKHI GFX_SRV) and the major-102 requirement
  (ENOEXEC).
- xe_huc_auth(XE_HUC_AUTH_VIA_GSC) for a HuC the media GuC authenticated:
  PXP 4.3 NEW_HUC_AUTH with the whole HuC object, five submissions 50 ms
  apart while the GSC replies pending (the message handle is handed back),
  OP_NOT_PERMITTED as already authenticated, then HECI1_FWSTS5 HUC_AUTH_DONE
  within 100 ms. As in Linux, any failure makes the HuC LOAD_FAIL, so query7
  type1 would then be ENODEV, but the GSC load continues. A GSC load failure
  never touches the HuC.
- xe_gsc_proxy_start, the request handler, proxy_query and
  validate_proxy_header, up to the CSME send/recv boundary.
- XE_FW_GSC around each run, the SW_PROXY and GSC_ER_COMPLETE actions, and
  the ER timer check that declares the GSC wedged.

Without a bound CSME component the worker behaves as Linux built without
CONFIG_INTEL_MEI_GSC_PROXY. xe_gsc_proxy_init's ENODEV is tolerated, the
firmware loads and authenticates the HuC, and then xe_gsc_proxy_start fails
with ENODEV after enabling and disabling the proxy interrupt. gsc_work
records LOAD_FAIL, an error state in which no later GT reset or resume
reloads the GSC. With the component (the MEI GSC proxy client below), the
proxy reaches PROXY_STATE_NORMAL, the GSC is RUNNING, and a GSC lost across
resume is reloaded in full.

NARF deviations, all fail-closed: lost MMIO (all ones) is never a set bit; an
unacknowledged GSC wake ends the run (Linux proceeds without it); a GSCCS job
that never retires blocks later submissions (Linux queues behind it); a
missing or malformed image or an unavailable private object leaves the GSC
unavailable where Linux fails the MTL probe.

The runtime supplies all three: GSCCS0, the stolen private object and the
CSME component ("MTL GSC in production" below).

Without `narf.intel.pxp=1` PXP stays refused with Linux's errnos. Linux
supports PXP only with CONFIG_INTEL_MEI_GSC_PROXY (xe_pxp_is_supported);
without it xe->pxp is NULL, and NARF matches that case on every native Xe
device without the option (with it, see "MTL/Arrow PXP behind
narf.intel.pxp=1" below):
- DRM_XE_DEVICE_QUERY_PXP_STATUS negotiates sizeof(drm_xe_query_pxp_status)
  (8). Any other nonzero size is EINVAL, and the exact size is ENODEV with
  nothing copied out.
- DRM_XE_EXEC_QUEUE_SET_PROPERTY_PXP_TYPE accepts NONE. HWDRM is ENODEV and
  any other session type EINVAL (exec_queue_set_pxp_type).
- GEM_CREATE runs its SET_PROPERTY chain (gem_create_user_extensions): a
  nonzero name or pad, or a property other than PXP_TYPE, is EINVAL; NONE is
  accepted; HWDRM is ENODEV (xe_pxp_key_assign on NULL). As in Linux, the
  chain's result applies only after argument, VM and allocation refusals, and
  a refused extension publishes no handle. The header is copied before the
  body, so EFAULT and EINVAL keep Linux's order.
- VM_BIND already accepted DRM_XE_VM_BIND_FLAG_CHECK_PXP; with no protected
  object it has no effect, as in Linux.
More than 16 GEM_CREATE extensions is Linux's E2BIG
(`FsError::ArgumentListTooLong`).

The GSC proxy cannot be completed over GSCCS alone: the GSC asks the driver to
relay its messages to CSME and back. PXP needs that relay (xe_gsc_proxy_init_done
gates xe_pxp's readiness). The relay is the MEI GSC proxy client
(`drivers/platform/src/mei_gsc_proxy.rs` over `mei.rs`'s client message
layer, after Linux drivers/misc/mei/gsc_proxy/mei_gsc_proxy.c and
`i915_gsc_proxy_component_ops`):
- Bind the CSME HECI1 PCI function (MTL-M 0x7E70, ARL-S 0x7F68, ARL-H 0x7770,
  MEI_ME_PCH15_CFG) to the integrated display device on bus 0.
- Find the firmware client with UUID f73db04-97ab-4125-b893-e904ad0d5464 by
  the HBM HOST_CLIENT_PROPERTIES walk and connect to it with per-client flow
  control (mei_cldev_enable).
- Provide a blocking `send(buf, len)` (mei_cldev_send) and a
  `recv(buf, 32 KiB)` (mei_cldev_recv) that return bytes or a negative errno.
It registers with `narf_drivers::gsc_proxy`, which the worker's `CsmeProxy`
binds; PXP above it runs only with `narf.intel.pxp=1`.

Threat assumptions. Without `narf.intel.pxp=1`, NARF writes no KCR register,
starts no session, creates no protected object or queue and offers no key to
invalidate (the PXP section below states what changes with it). The GSC
firmware is trusted, hardware-authenticated code: NARF checks only the image
layout and the compatibility major. The private object it receives is
GSC-owned until an FLR. The proxy relays opaque GSC/CSME messages and checks
only their headers and sizes. HuC authentication through the GSC exercises
the PXP firmware client but starts no PXP session.

Fixtures (`drivers/gpu/intel_gpu_media_gt`):
- `smoke_media_gt_gsc_wa_14015076503_brackets_stop_and_admits_scheduling` and
  `smoke_media_gt_gsc_without_option_retains_and_failed_reset_clears` (the
  media GuC model).
- `smoke_media_gsc_option_grammar_and_wa_14015076503_registers`.
- `smoke_media_gsc_load_uploads_queries_authenticates_huc_and_stops_at_proxy`,
  `smoke_media_gsc_load_refusals_leave_the_guc_huc_running`,
  `smoke_media_gsc_huc_auth_retries_failures_and_skips`,
  `smoke_media_gsc_proxy_csme_boundary_and_reload_after_resume` and
  `smoke_media_gsc_er_complete_wedges_only_on_an_expired_timer` (a GSC
  firmware model behind GSCCS and a CSME model).
- `smoke_xe_pxp_type_query_and_bo_refuse_with_linux_errnos` (native Xe on the
  MTL GuC model).

None of this is physical Intel evidence.

In the combined stop, `media_power_down` (`xe_uc_gucrc_disable`) comes first,
then the GuC stop, then the Wa_14015076503-bracketed GRDOM_FULL, which is
Linux's `gt_reset_worker` order.

Review against Linux b90c984d agreed on the following:
- `query_pxp_status`: size 0 negotiates 8; any other size is EINVAL; the exact
  size reaches `xe_pxp_get_readiness_status(NULL)`, which is ENODEV.
- `exec_queue_set_pxp_type`: NONE is 0, a non-HWDRM type is EINVAL, and
  HWDRM is ENODEV.
- `gem_create_user_extensions` checks the header (pad, name), then the
  set-property body (property, pad), then `gem_create_set_pxp_type`. Its
  result applies after the object exists.
- `xe_gsc_wa_14015076503` sets `HECI_H_GS1` ER_PREP, then `HECI_H_CSR` IG
  with RST clear and a 200 ms hold before GRDOM_FULL. The clear comes after,
  even when the reset fails. It applies only to media 13.00 with GSC firmware
  loaded.
- Media scheduling beside loaded GSC firmware is admitted only with
  `narf.intel.gsc=1`.


### MTL GSC in production: GSCCS0, the stolen private object and the worker

Behind `narf.intel.media_gt=1` and `narf.intel.gsc=1` the GSC worker now runs
on hardware paths. With either option off, GT0 and GT1 behave exactly as
before: no firmware is fetched, GSCCS0 is not scheduled, no DSM is claimed
and no GSC register is written.

GSCCS0 follows xe_hw_engine.c's XE_HW_ENGINE_GSCCS0 entry: class OTHER,
GUC_GSC_OTHER_CLASS, OTHER_GSC_INSTANCE 6 and GSCCS_RING_BASE 0x11a000. It
has its own XE_FW_GSC domain (FORCEWAKE_GSC / FORCEWAKE_ACK_GSC; Linux enum
value 15, bit 13 of NARF's packed media-domain bitmap). xe_gsc_init fetches
`i915/mtl_gsc_1.bin`, and the media GuC schedules GSCCS0 only when that
image is available, as check_gsc_availability does. If it is not, the
runtime writes GUNIT_GSC_INTR_ENABLE 0 and GUNIT_GSC_INTR_MASK all ones.
When scheduled, GSCCS0 gets:
- the "MTL GSCCS IDLE MSG enable" reg_sr pair before ring enable (masked
  clear of RING_PSMI_CTL IDLE_MSG_DISABLE, RING_PWRCTX_MAXCNT IDLE_WAIT_TIME
  0xA) and the usual RING_MODE;
- RING_NOPID in every NONPRIV slot, since no whitelist entry matches OTHER;
- an ADS class entry with mapping, enable mask, golden LRC (an empty WA job
  over dg2_xcs offsets) and regsets that include the masked PSMI save;
- the 600 ms preempt-timeout floor of hw_engine_init_early.
xe_hw_engine_is_reserved holds: GT1's publication, queries and placements
never contain GSCCS0, class lookups skip it, and the scheduler refuses user
work on it. The kernel queue runs the worker's GSC_HECI_CMD_PKT and
GSC_FW_LOAD inline on GSCCS0, one job at a time, while the worker takes a
nested reference on the GSC wake the media GuC holds. The tile IRQ owner
programs xe_irq_enable_hwe's GSC enable and masks, decodes bank-0 bits 31
(GSCCS0) and 30 (HECI2) into GSC events, and resets them as gt_irq_reset
does.

The 4 MiB private object is a device-lifetime claim in DSM, shared with FBC
through a registry keyed by the DSM base. The CFB carve avoids the GSC
claim. The GSC placement avoids the WOPCM, the Wa_14019821291 region, every
aperture DM page (the boot framebuffer) and recent CFB claims, and proves
each page is not system RAM. The claim is never released or moved, because
the GSC may use it until an FLR, which NARF never performs. Its GGTT mapping
uses XE_GGTT_PTE_DM, added to the encoder only for it
(xelpg_ggtt_pte_flags: PRESENT | DM | WB PAT over stolen_base + offset). It
sits at a fixed window directly above the GT arena (288 MiB), outside the
CPU aperture, so the FBC survey stays valid. No arena hands it out, clears
it or invalidates it, and every GT1 start rewrites identical entries. The
CPU writes the image through BAR2 at io_base + offset, as
xe_ttm_stolen_io_offset does.

The runtime keeps one GSC owner per device. When each media GuC reaches
Running, the owner attaches that GuC's arena objects (version packet, HuC
packet for a GSC-headered HuC, and a proxy channel only beside a bound CSME
component) and calls xe_gsc_load_start. Before a media stop the runtime lets
a running load finish, as xe_gsc_stop_prepare does; a stop that cannot wait
makes the load LOAD_FAIL. The objects are freed after the verified stop, or
retained with an unproven one. Without a CSME component the result matches
Linux without CONFIG_INTEL_MEI_GSC_PROXY:
- the firmware loads and the compatibility query must report major 102;
- a HuC the media GuC authenticated is also authenticated via the GSC, and a
  failure there makes query7 type1 ENODEV;
- proxy start fails with ENODEV and the GSC is LOAD_FAIL, which no GT reset
  or resume reloads.
`intel_gpu_gt::register_csme_proxy` / `unregister_csme_proxy` expose the
`CsmeProxy` send/recv hook; `sync_csme_proxy` binds the MEI GSC proxy client
(drivers/platform) through `narf_drivers::gsc_proxy` when it registers.

Fixtures, all under `drivers/gpu/intel_gpu_media_gt`:
- `smoke_media_gt_gsccs_identity_policy_and_reserved_exclusion` and
  `smoke_media_gt_gsccs_schedules_primes_and_executes_gsc_jobs`, on the
  media GuC model, cover registration, the reg_sr pair, NONPRIV, the ADS,
  priming, the preempt floor, both GSC instruction shapes on the queue,
  reserved exclusion, verified stop and the option-off sequence.
- `smoke_mtl_media_gt_gsc_irq_enables_decodes_and_resets` covers the GSC
  sources and check_gsc_availability's pair.
- `smoke_media_gsc_stolen_object_avoids_fbc_boot_fb_wopcm_and_gsc_wa` and
  `smoke_media_gsc_dm_ptes_encode_stolen_and_survive_incarnations` cover the
  claim and the DM window over a RAM-backed BAR.
- `smoke_media_gsc_owner_without_mei_loads_auths_huc_and_ends_load_fail` and
  `smoke_media_gsc_owner_proxy_resume_reload_and_interrupted_load` cover the
  production owner end to end against a GSC firmware model, including GT
  reset, D3hot re-classification, D3cold reload with a model CSME component,
  and an interrupted load.
These fixtures are native models only: none has been run on physical Intel
hardware. Still open are GSC ER-timeout recovery beyond wedging and silicon
acceptance; PXP above the GSC is the next section.

REGISTER_CONTEXT for the kernel GSCCS0 context uses
`EngineSet::registration_mask`, which maps a kernel-only engine to
`BIT(logical_instance)`, as `xe_gsc_init_post_hwconfig` creates the kernel GSC
queue; UAPI admission keeps the filtering mask. `route_gsc` proves access on
the enable register only, since all-ones is the mask registers' valid
`gt_irq_reset` value.

Review against Linux b90c984d agreed on the following:
- GSCCS0 is at `GSCCS_RING_BASE` 0x11a000, GuC class 5
  (`GUC_GSC_OTHER_CLASS`), hardware class OTHER 4, `OTHER_GSC_INSTANCE` 6.
- Its forcewake is `FORCEWAKE_GSC` 0xa618 with ack 0xdf8.
- `MTL GSCCS IDLE MSG enable` applies to MEDIA_VERSION(1300) class OTHER.
- Class OTHER is reserved (`xe_hw_engine_is_reserved`).

Known stall: copying the 4 MiB GSC image into stolen memory is about 1M
uncached BAR2 writes in one GT-worker poll. It happens once at load, off
any present path. With `media_gt=1` and `gsc=0`, the 0/~0 GSC interrupt pair
is not written, per the options-off rule.

### MTL/Arrow PXP behind narf.intel.pxp=1

`narf.intel.pxp=1` is a new strict default-off option with the shared
pre-`--` grammar. It is admitted only with `narf.intel.media_gt=1` and
`narf.intel.gsc=1`. Without it nothing below runs: no KCR register, KCR
interrupt route or GSC client object is touched, and every uAPI refusal of
the previous section stays as
`smoke_xe_pxp_type_query_and_bo_refuse_with_linux_errnos` pins it. `intel_gpu_gt::media::pxp` ports Linux 7.4-rc4 xe_pxp.c and
xe_pxp_submit.c.

Init and resources (xe_pxp_init). Once per device, on the first GT1 that
runs with GSCCS0 scheduled, PXP starts when the GSC firmware is loadable, a
HuC is staged on the media GuC (below media 35 PXP needs the HuC, so
`narf.intel.huc=1` is in effect required) and GT1 has a VCS. Otherwise it
logs the unsatisfied dependency and `xe->pxp` stays NULL (ENODEV, as Linux's
"Skipping PXP due to unsatisfied FW deps"). Init writes KCR_INIT's masked
ALLOW_DISPLAY_ME_WRITES enable (0x40004000), allocates the GSC client object
(three private system pages: batch, msg_in, msg_out) and a random host
session handle with bits 56..63 clear. A failed allocation disables KCR
again; Linux then fails the probe, NARF leaves PXP disabled. The status
starts at NEEDS_TERMINATION with key instance 1.

Submissions. The media GuC gains xe_pxp's two kernel queues, one job at a
time:
- GSCCS0 runs the client's GSC_HECI_CMD_PKT batch from its own private PPGTT
  (pxp_pkt_submit on gsc_res.q), started by __emit_job_gen12_simple as
  ring_ops_gen12_gsc does. The object sits at PPGTT 0x100000 (Linux: 0,
  which NARF's PPGTT builder keeps unmapped); the packet names msg_in and
  msg_out at +4 KiB and +8 KiB.
- GT1's first VCS runs xe_pxp_submit_session_termination's stream (MFX_WAIT,
  PXP off, MI_SET_APPID, PXP on with the PPHWSP 0x100 scratch store,
  CRYPTO_KEY_EXCHANGE, MFX_WAIT) inline in a kernel context's ring; Linux
  runs it as a GGTT batch. Both are privileged. Only that exact stream of one
  session is admitted.
gsccs_send_message writes the GSC header (HECI_MEADDRESS_PXP 17, the host
session handle) and message, poisons the reply header, waits HZ for the job
(ETIME), retries 40 times 50 ms apart while the GSC replies pending (handing
its message handle back; EAGAIN after the last), checks the reply header
(xe_gsc_read_out_header) and poisons msg_in again. Only the reply's status is
read; a nonzero one is EIO.

State machine. The status, the activation and termination completions, the
key instance and the queue list follow xe_pxp.c. pxp_start runs in the
ioctl: readiness (EBUSY while not ready), then the wait_for_idle loop with
its 500 ms termination and 300 ms activation bounds (ETIMEDOUT; FsError has
no ETIMEDOUT, so the ioctl sees ETIME). The hardware half runs in the GT
runtime worker, the only owner of the media GuC's queues: the ioctl posts the
start or termination it owes and waits for its outcome, which carries the
Linux errno back.
- __pxp_start_arb_session: KCR_SIP bit 15 already set is EEXIST; PXP 4.3
  INIT_SESSION (api 0x00040003, command 0x36, stream_id APPID(0xf) | VALID,
  buffer_len 60, protection mode ARB); then KCR_SIP bit 15 within 250 us
  (ETIMEDOUT). ACTIVE on success, ERROR otherwise.
- pxp_terminate_hw: the VCS termination (HZ, ETIMEDOUT), KCR_SIP bit 15
  clear within 250 us, KCR_GLOBAL_TERMINATE = 1, then INVALIDATE_STREAM_KEY
  (command 7, stream_id SESSION_VALID | SESSION_ID(0xf), buffer_len 12). A
  failure is ERROR with the termination complete; success waits for
  KCR_PXP_STATE_RESET_COMPLETE.
- The tile IRQ owner routes CRYPTO_RSVD_INTR_ENABLE = 0xe << 16 and
  CRYPTO_RSVD_INTR_MASK = ~(0xe << 16), decodes the bank-0 GEN11_KCR (19)
  identity as class OTHER, OTHER_KCR_INSTANCE (4), and resets both as
  gt_irq_reset does. KCR_PXP_STATE_TERMINATED and
  KCR_APP_TERMINATED_PER_FW_REQ run pxp_terminate (the key instance moves on
  if a session was active, every PXP queue is killed, the hardware
  terminates); RESET_COMPLETE runs pxp_terminate_complete. A request while
  one runs needs an additional termination; a completion that arrives with a
  request is dropped. Without the KCR route terminations never complete and a
  start that needs one is ETIMEDOUT.
- Readiness (xe_pxp_get_readiness_status) is the worker's observation of a
  running GT1: EIO for a GSC or HuC firmware error state, 1 once
  HECI1_FWSTS5 HUC_AUTH_DONE and HECI1_FWSTS1 PROXY_STATE_NORMAL are both
  set, else 0. Lost MMIO reads as not done. A stopped GT1 reports 0.

GT1 stop and start. Every GT1 stop (GT0 reset or recovery, runtime park,
system suspend, fault cleanup, a media GuC that leaves Running) first runs
xe_pxp_pm_suspend: a PXP job in flight finishes (each step is bounded) or,
when the stop cannot wait or GT1 already left Running, fails as its job
would. An ACTIVE session (or a used NEEDS_TERMINATION) moves the key on,
kills every PXP queue and marks a termination for resume; the status becomes
SUSPENDED and readiness 0. A start an ioctl posted but the worker never began
is abandoned (its waiter sees EIO). Pending KCR causes are dropped, and a
termination still awaiting its KCR completion counts as complete: GT1's
GRDOM_FULL ends it and resume always leaves NEEDS_TERMINATION. The next GT1
start runs xe_pxp_pm_resume once the GSC worker is idle: KCR enabled again,
NEEDS_TERMINATION, and the deferred termination as the ON_RESUME events work.
Linux runs the suspend only for system and runtime suspend; NARF also runs it
for a media GT reset, which loses the KCR state the same way.

uAPI with `xe->pxp` published:
- DRM_XE_DEVICE_QUERY_PXP_STATUS: size 0 negotiates 8, another size is
  EINVAL, the exact size returns status 0/1 with supported_session_types
  BIT(DRM_XE_PXP_TYPE_HWDRM), or EIO. The async path holds a runtime-PM
  reference over it, as Linux's guard does.
- EXEC_QUEUE_CREATE with PXP_TYPE HWDRM (a later NONE keeps it) runs
  xe_pxp_exec_queue_add under a runtime-PM reference: pxp_start, then
  __exec_queue_add, which retries while PXP is not ACTIVE. Errors keep their
  errno (EBUSY, EIO, EEXIST, ETIME, EAGAIN as EWOULDBLOCK). The queue then
  holds that reference on the PXP list, so the function never runtime
  suspends under it; destroy takes it off. Native Xe files now take
  EXEC_QUEUE_CREATE through the async dispatch; the synchronous path answers
  a start still running as EBUSY. RCS/CCS PXP queues get CTX_CTRL_RUN_ALONE
  in every LRC (XE_LRC_CREATE_RUNALONE, graphics below 20); a parallel
  compute PXP queue, impossible with MTL's single CCS, is EOPNOTSUPP.
- GEM_CREATE's SET_PROPERTY HWDRM marks the object with the current key
  instance (xe_pxp_key_assign).
- VM_BIND MAP with DRM_XE_VM_BIND_FLAG_CHECK_PXP of a protected object whose
  key is stale, and EXEC on a PXP queue whose VM maps such an object
  (xe_vm_validate_protected), are Linux's ENOEXEC, which FsError cannot
  carry: NARF answers EINVAL. UNMAP and UNMAP_ALL are never checked.
- A killed queue is ECANCELED on EXEC, as Linux's reset_status reports.
- A protected object is refused as a framebuffer (drm/card.rs): NARF programs
  no plane decryption. Linux decrypts a current one and shows black for a
  stale one.

Threat assumptions with the option:
- Key material never reaches NARF. The GSC firmware and KCR hold every
  session key; the driver sees only the key-instance counter, the session
  state and the host session handle, an identifier that is random and never
  logged. Logs name dependencies and errnos only.
- The GSC firmware is trusted, hardware-authenticated code. NARF checks only
  the reply header and the status word; it interprets no other reply byte.
- Failures fail closed: any failed start or termination is ERROR, and every
  later PXP request is EIO until the next GT1 stop and start clears it (as
  Linux's suspend may clear it).
- Killing a PXP queue closes its admission but does not preempt a job
  already running; the invalidated key makes such a job's output useless.
  Linux also cancels the GuC context.
- Key checks race with terminations by design, as Linux notes: one
  submission or bind may pass just before a termination.
- A protected object's pages hold ciphertext; CPU mmap and binds without
  CHECK_PXP stay allowed, as in Linux.
- The CSME proxy relays opaque GSC/CSME messages, as before.

Fixtures:
- `drivers/gpu/intel_gpu_pxp` (a GSC firmware and KCR model):
  `smoke_pxp_option_grammar_and_linux_formats`,
  `smoke_pxp_arb_session_start_sends_the_linux_init_session_packet`,
  `smoke_pxp_terminates_on_suspend_and_resume`,
  `smoke_pxp_key_check_refuses_a_stale_object_after_termination`,
  `smoke_pxp_start_failures_keep_linux_errnos` and
  `smoke_pxp_stop_quiesces_or_aborts_hardware_work`.
- `drivers/gpu/intel_gpu_media_gt`:
  `smoke_mtl_media_gt_kcr_irq_enables_decodes_and_resets` (the IRQ model),
  `smoke_media_gt_pxp_jobs_run_on_gsccs_ppgtt_and_the_first_vcs` (the media
  GuC model) and `smoke_xe_pxp_enabled_queues_objects_and_stale_key_checks`
  (native Xe with a published `xe->pxp`).
The packet bytes, termination words, register values and errnos are the
Linux ABI's, never recorded from this implementation. Nothing here has run
on physical Intel hardware. Not covered natively: the RUN_ALONE bit in a
submitted LRC, the runtime's init/suspend/resume wiring (no runtime model),
and the real GSC firmware's acceptance of NARF's PPGTT address and inline
VCS termination.

### Xe OA streams on the main-GT OAG unit — native fixtures added

Sources are Linux b90c984d `xe_oa.c`, `xe_oa_types.h`, `regs/xe_oa_regs.h`,
`xe_observation.c`, `xe_query.c::query_oa_units` and `xe_drm.h`. The
module is `intel_gpu_oa`.

The exact boot opt-in `narf.intel.oa=1` reserves one 16 MiB coherent GGTT
buffer per card before scheduling starts, the same rule as EU-stall
sampling. A stream that opens a larger buffer, up to the 128 MiB Linux
maximum, grows the reservation at attach; the reservation never shrinks.
The GT owner keeps it. Writing OACONTROL=0 and the masked
MMIO-trigger disable follows `__xe_oa_init_oa_units`. The OAG unit is
published only for main-GT profiles the source qualifies: DG2 12.55,
MTL/Arrow 12.70/12.71/12.74, BMG 20.01/20.02 and LNL 20.04. Format masks
follow `xe_oa_init_supported_formats`. The register whitelist follows
`xe_oa_is_valid_config_reg_addr` for the main GT's graphics version.
PTL, Gen12 and the media-GT OAM units are not published. The production GuC runtime supplies the main GT observation unit. Publishing OAM requires a separate media GT counter owner and register window.

Query 8 returns the source's zero-unit reply until that owner and the
execution epoch are published. After that it returns one OAG unit (id 0,
gt 0) with its published render and compute engines in hw-engine order and
the cached `xe_oa_timestamp_frequency`. On 12.55 and 12.70–12.74
(Wa_18013179988, including its rules continuation) it applies RPM_CONFIG0's
CTC shift, read once at publication. Capabilities are BASE,
OA_BUFFER_SIZE, WAIT_NUM_REPORTS and OA_UNIT_GT_ID. SYNCS and OAM are not
advertised.

Observation routing copies the parameter in and checks extensions. It then
routes type 0 to OA and type 1 to EU-stall, whose nonzero op is EINVAL
first. Every other type or op is EINVAL. OA open, ADD_CONFIG and
REMOVE_CONFIG keep the source's check order and C widths:

- ENODEV without the owner.
- Sixteen-extension E2BIG, then EFAULT and EINVAL on records and
  properties. Property values are applied in chain order, with u32 unit
  and metric ids and an int wait count.
- The exec-queue lookup: ENOENT, then EOPNOTSUPP for width above one.
- Privilege: EACCES unless current CAP_PERFMON or CAP_SYS_ADMIN (paranoid
  is always on). Then the sample, engine, format, exponent and wait checks.
- EBUSY for a second stream on the card. Syncs, then the metric set
  (EINVAL), then the buffer.

Configurations live in a per-card registry for the card's lifetime. Uuids
are checked with `uuid_is_valid`, duplicates are EADDRINUSE, and ids are
the lowest free from 1. Registers are read and checked one at a time.

Open programs the source metric set. On DG2 this includes Wa_1508761755
DOP gating, and on Xe2 the PEC trigger bits. It writes OA_DEBUG,
OAGLBCTXCTRL and SQCNT1. The configuration becomes MI_LOAD_REGISTER_IMM
groups of at most 126 registers. Up to 378 registers go into each
privileged kernel ring job on the stream's engine. Each job retires before
the next is queued, then the 500 us NOA delay passes. Only then does the
stream enable.

Enable follows `xe_oa_init_oa_buffer`'s head, buffer and tail order and
zeroes the buffer before OACONTROL is set. On Xe2 it also sets PES
disaggregation, and with sampling the ring is a report-multiple circular
size. A 200 Hz poll applies the source landing rule: subtract the partial
report, then walk back until the following report's header has landed. It
latches pollin at WAIT_NUM_REPORTS.

Reads copy whole reports and clear the id and timestamp. When reports
straddle the ring end, they zero the whole report instead. Reads then
write OAHEADPTR. EIO comes from relevant OASTATUS bits, which are cleared
by RMW. ENOSPC and EIO keep pollin; everything else clears it. Other
results follow the source:

- Disabled or non-sampling streams and periodless blocking reads are
  EINVAL. Short buffers are ENOSPC, and an empty ring is EAGAIN.
- STATUS maps the last OASTATUS to the uapi bits. INFO reports the
  buffer size.
- CONFIG accepts only metric set and syncs. It is ENODEV for an unknown
  set and returns the previous id.

Disable clears OACONTROL and waits for the counter. On 12.55/12.70 it also
waits for the OA TLB invalidation. Timeouts proceed as the source's
logged-only waits do.

Close disables the stream and undoes the metric set under the owner, and
the next exclusive open can follow. An open stream blocks GT idle, so
runtime park is refused, as the source's stream-lifetime runtime-PM and
forcewake references do.

GT stop, reset and system suspend make the stream terminal (ENODEV),
counters are halted and the metric set is undone. A buffer the unit was
ever pointed at is released only after the existing GuC/DMA/full-GT reset
proofs. Access loss, an all-ones read or a tail outside the owned ring
poisons the unit.

NARF bounds and differences from the source:

- A buffer above the current reservation grows it up to 128 MiB at
  attach; growth returns ENOMEM while a user mapping aliases the old
  pages or when the allocator refuses, where the source would allocate.
  The sysfs `oa_buffer_size` node publishes the live reservation.
- Configurations are capped at 4096 registers (ENOMEM), 131072 registers
  per card (ENOMEM) and 1024 ids (ENOSPC).
- Current authority is required at every read and control (EACCES); the
  source checks only at open and mmap.
- OA syncs and OAR/OAC exec-queue streams are implemented with native
  fixtures, including per-context OAR/OAC programming at enable/disable;
  NO_PREEMPT (property 9) holds the bound queue at timeslice 0 and
  preempt timeout 0 from enable until disable, restoring the saved
  schedule at disable and on close (#1774); MI_REPORT_PERF_COUNT query
  sampling (open properties 14/15: the opener's per-batch report
  buffer in the bound context's PPGTT) emits one query per batch in
  the exec path (#1774).
- There is no mmap of the OA buffer, no `metrics/<uuid>/id` sysfs
  directory and no `observation_paranoid` sysctl.
- Media-GT OAM, OAM_SAG and MERT units, PTL and Gen12 are not published.

Fixtures are in
`drivers/gpu/intel_gpu_oa`:

- `smoke_oa_query_units_formats_and_timestamp`
- `smoke_oa_open_property_privilege_and_errno_order`
- `smoke_oa_buffer_size_min_max_default_out_of_range`
- `smoke_oa_config_registry_errno_order_ids_and_whitelists`
- `smoke_oa_lri_groups_and_ordered_ring_jobs`
- `smoke_oa_source_register_sequences_per_profile`
- `smoke_oa_tail_landing_partial_reports_and_wait_threshold`
- `smoke_oa_read_wrap_clear_enospc_status_eio_and_info`
- `smoke_oa_descriptor_authority_blocking_config_and_reopen`
- `smoke_oa_reset_suspend_loss_and_buffer_retention`
- `smoke_oa_hardware_bmg_reservation_ring_job_read_and_reset_retirement`

The first ten drive real units, sessions and descriptors against a
register and memory model. The last drives the real BMG `GuCGt` through the
existing GuC model:

- the reservation before scheduling and the published facts;
- the configuration's LRI job, registered, executed and retired through
  the GuC scheduler;
- programming, the tail service and a read;
- stop and reset, where the buffer survives GuC stop until GRDOM_FULL.

The model now recognises a render ring whose first LRI targets a source OA
register as a configuration job. The asynchronous runtime backend has no
fixture of its own. Silicon and Mesa acceptance remain open.

**Device coredump against `xe_devcoredump.c`.** Linux prints text sections
in this order:

- the reason, kernel, module, times and process;
- `xe_device_snapshot_print`, then the GT and tile;
- the GuC log and the GuC CT;
- the GuC exec-queue contexts with their LRC, HWSP and HWCTX bodies;
- the job's batch addresses;
- one HW-engine register snapshot per engine, from GuC error capture or
  `xe_engine_manual_capture`;
- the DUMPABLE VMAs.

NARF's CAP_SYSLOG-gated version-3 bundle already holds the GuC log and CT
copies, scalar context facts, eight bounded LRC (including PPHWSP), ring
and group-scratch slots, and bounded DUMPABLE system/WC/USERPTR prefixes.
These differences remain:

- Format and lifetime. NARF writes a binary bundle, not ascii85 text, and
  has no `devcoredump/data` class node. Its protected descriptor uses a
  generation-matched clear and a two-buffer limit instead of the one-hour
  release.
- Header. There is no process name/pid, kernel release or
  `xe_device_snapshot_print` block.
- HW engines. The sanitized report keeps only six redacted registers per
  engine and four globals. NARF does not register GuC error-capture lists
  (ADS capture registration and STATE_CAPTURE parsing). It does not take
  the full manual list: HWSTAM, HWS_PGA, RING_HEAD/TAIL/CTL, MI_MODE, MODE,
  ESR/EMR/EIR/IMR, IPEHR, INSTDONE, INDIRECT_RING_STATE, CURRENT_LRCA, the
  64-bit ACTHD/BBADDR/START/DMA_FADD/EXECLIST pairs, RCU_MODE, SC_INSTDONE,
  SFC_DONE and FORCEWAKE_GT.
- Contexts and job. There are no exec-queue policy fields (timeouts,
  timeslice, priority, pending state, workqueue head/tail) and no decoded
  per-lane batch address section.
- VM. Local-memory and oversized VMAs are marked unavailable or truncated
  instead of being dumped whole.

**i915 perf surfaces against `i915_getparam.c`, `i915_query.c` and
`i915_perf.c`.** These are not implemented:

- DRM_I915_PERF_OPEN, PERF_ADD_CONFIG and PERF_REMOVE_CONFIG, and query
  item 3 (PERF_CONFIG).
- GETPARAM 54 (PERF_REVISION) stays 0, as the truthful no-i915-perf signal.
- GETPARAM 57 (OA_TIMESTAMP_FREQUENCY) stays 0. Linux returns the clock,
  with the same Wa_18013179988 CTC shift on DG2 and 12.70–12.74.

Porting i915 perf is not plumbing over the Xe OA unit. Its records carry
`drm_i915_perf_record_header` sample and loss records, it has its own
property set and separate mux, boolean and flex configuration lists, and
its metrics are in sysfs. GETPARAM 57 also needs the CTC shift cached
without the OA opt-in. GETPARAM 46/47 already return the source's EINVAL
from 12.55 onward.

**EU-stall open errno.** EU-stall open now returns ENODEV without a
published owner before it returns EACCES for missing privilege, as
`xe_eu_stall_stream_open` does. It used to return EPERM first. Later
read/control refusals stay EPERM.

Changed fixtures:

- `smoke_eu_stall_descriptor_current_authority_install_cancel_and_last_close`
  expected EPERM for a denied open. It now expects EACCES.
- `smoke_lnl_eu_stall_raw_query_open_cancel_reopen_and_full_reset_owner`
  expected EPERM for its raw-ioctl denial and for its revocation across the
  attach await. Both now expect EACCES.

### GuC error capture, coredump text sections and OA remainder — native fixtures added

Sources are Linux b90c984d `xe_guc_capture.c`, `xe_guc_capture_types.h`,
`abi/guc_capture_abi.h`, `abi/guc_log_abi.h`,
`xe_guc_ads.c::guc_capture_prep_lists`, `xe_hw_engine.c`,
`xe_guc_submit.c` (exec-queue snapshot and timeout handler),
`xe_sched_job.c`, `xe_devcoredump.c`, `xe_oa.c` (mmap and sysfs) and
`xe_observation.c`. The new module is `intel_gpu_error::capture`.

**GuC error-capture lists.** With `narf.intel.devcoredump=1` the runtime
prepares capture on the primary GuC before scheduling, beside the EU-stall
and OA reservations. It builds the source lists: the global FORCEWAKE_GT
list, the XeLP (Gen12) or XeHPG (12.55 and later) render/compute class list,
the video-enhance SFC_DONE list and the 27-register engine-instance list. The
steered SAMPLER/ROW INSTDONE extension (plus the four XeHPG SC/GEOM
registers) is added for each fused DSS, with HWCONFIG's DSS-per-group or the
source fallback. `guc_capture_prep_lists` lays them out page by page after a
zero-descriptor page and fills guc_ads capture_instance, capture_class and
capture_global. Absent classes, empty lists, lists past the worst size and
the VF owner point at the zero page. NARF puts the lists in their own
worst-size GGTT object instead of inside the ADS object: 11 pages on XeHPG,
9 on XeLP. The object is written only during the submission reload while the
GuC is proven stopped. It is freed with the boot owner after the existing
reset proofs. The media GuC registers no lists.

**STATE_CAPTURE_NOTIFICATION.** Without registered lists a 0x8002 G2H stays a
protocol loss, as before. With them, its one status dword is checked
(NOSPACE is counted), and the GT owner then runs `__guc_capture_process_output`
over the log's 1 MiB capture region. It reads the type-2 state header,
replaces untrusted or overflowed pointers with the whole region, and runs
`guc_capture_extract_reglists`. That covers the group and capture headers,
dword reassembly across the ring end, skipping unknown capture types, cloning
global and class lists for dependent engine resets, replacing stale nodes with
the same GuC id, and clipping register counts. It then publishes the read
pointer, clears flush-to-file and sends LOG_BUFFER_FILE_FLUSH_COMPLETE (0x30,
type 2), retrying while the CT is full. NARF bounds:

- Four parsed nodes, against the source's 1536. When none is free the newest
  unlocked node is reused; that is what the source's reverse walk does,
  despite its comment.
- At most 256 capture groups per notification.
- Current authority is checked for each group. If it ends, the read pointer
  is not published and no flush-complete is sent.

**Matching and the manual fallback.** A coredump looks for a GuC node by the
guilty queue's template GuC class, GuC id and LRC GGTT address, as
`xe_guc_capture_get_matching_and_lock` does. NARF accepts any reported
instance among the queue's placements, where the source compares only
q->hwe. The source's node lock becomes a deferred release at the next
notification, because extraction and the coredump never overlap under the GT
owner. Without a match, the node taken at the context's timeout is used. That
read follows `guc_exec_queue_timedout_job`: the first placement's global,
class and instance lists, read under the existing forcewake proof before the
schedule disable is sent. Three differences from the source:

- It omits the steered extension, whose unicast reads need MCR steering
  writes in the failure path.
- Its guc_id and LRCA stay zero, as the source's do.
- Because NARF captures the bundle in the same poll as the timeout, a GuC
  node from a later reset under the disable is not substituted.

**Coredump version 4.** `NARFCDMP` version 4 keeps every earlier offset and
appends a `NARFXETX` section: a 64-byte header and 32 KiB of text at 0x275380,
for a total of 0x27d3c0 bytes. Header bit 5 and words 172/176/180 describe it.
The text follows `__xe_devcoredump_read`:

- The header facts: the reason, PCI ID and revision, GMD_ID IP version (0.0.0
  on Gen12 and DG2, as gt->info.gmdid) and CS reference clock. These are
  sampled once at preparation.
- The guilty queue's `xe_guc_exec_queue_snapshot_print` fields: GuC id, name,
  class, logical mask, width, the 5000 ms timeout, timeslice, the 500000 us
  preemption timeout, EXEC_QUEUE_STATE bits implied by NARF's phase, and the
  KERNEL and LOW_LATENCY flags. Groups add the workqueue descriptor and up to
  64 entries.
- The per-lane batch addresses of `xe_sched_job_snapshot_print`.
- One `xe_engine_snapshot_print` engine block: source, coverage, forcewake
  domain, registers in descriptor order with 64-bit pairs joined, and the
  steered registers with their DSS index.

The GuC log, CT, LRC and VM blocks name their binary sections. Snapshot time,
process, kernel release and Ref are printed as unavailable. "Reserved" is
always no, since NARF reserves no published engine. The text reads no
register, allocates nothing and ends with `output_truncated=1` on overflow.

The engine block discloses GGTT and PPGTT addresses (ring start, ACTHD,
BBADDR, DMA_FADD, HWS_PGA, CURRENT_LRCA, the GuC LRCA), ring offsets, IPEHR's
instruction header and error and interrupt state. It appears only in the
CAP_SYSLOG-gated bundle. The public `error` report keeps its redacted
six-register whitelist. Without the opt-in the ADS, the log and the bundle are
unchanged apart from the version.

**OA remainder.**

- *mmap.* OA descriptors now apply `xe_oa_mmap`'s checks in order: EACCES
  without privilege, EINVAL unless the length is the whole buffer, then
  EINVAL for write, exec, MAP_SHARED or MAP_SHARED_VALIDATE. The offset is not
  checked, as in the source. The maximum protection is read. A request that
  passes every check returns ENODEV: NARF's syscall layer maps device frames
  only for MAP_SHARED, and its private fallback would copy through read(),
  which consumes reports. The read-only private PFN mapping, with its
  DONTCOPY and DONTEXPAND rules, needs that layer (outside `drivers/gpu`).
- *sysfs.* With the OA opt-in, `metrics/` appears under the card node.
  ADD_CONFIG publishes `<uuid>/id` with the decimal id under the registry
  lock, and REMOVE_CONFIG removes it. A refused duplicate publishes nothing.
- *sysctl.* `dev.xe.observation_paranoid` (0644, 0..1, default 1, EINVAL out
  of range) is registered through the procfs sysctl registry when the first
  Intel card is published; the source registers it at module load. At 0 every
  OA and EU-stall privilege gate allows the caller. NARF's per-read authority
  checks follow the same gate.
- *Media-GT OAM, PTL and Gen12* are still not published. OAM needs the media
  GT's OA unit, the OAM register block and a second query-8 unit tied to the
  standalone media GT owner. PTL and Gen12 OA layouts are not ported.

**i915 perf.** PERF_OPEN, PERF_ADD_CONFIG, PERF_REMOVE_CONFIG, query item 3 and
GETPARAM 54/57 remain as recorded in the previous subsection.

Fixtures:

- `smoke_guc_capture_ads_lists_follow_prep_lists_per_family`
- `smoke_guc_capture_extracts_groups_matches_and_acknowledges`
- `smoke_guc_capture_dependent_resets_wrap_overflow_and_reuse`
- `smoke_guc_capture_manual_fallback_reads_source_lists`
- `smoke_coredump_xe_text_section_queue_job_engine_and_bounds`
- `smoke_hardware_guc_capture_ads_g2h_extraction_and_guc_engine_snapshot`
- `smoke_hardware_guc_capture_timeout_manual_fallback_snapshot`
- `smoke_hardware_guc_capture_option_off_unchanged`
- `smoke_oa_mmap_source_checks_and_private_pfn_refusal`
- `smoke_oa_metrics_sysfs_uuid_id_follows_registry`
- `smoke_observation_paranoid_sysctl_range_and_gate`

The three hardware fixtures drive the real BMG `GuCGt` through the GuC
model. The model now answers the capture flush-complete.

Changed fixtures. Each asserted the bundle version 3 or the total 0x275380
and now asserts version 4 or 0x27d3c0:

- `smoke_coredump_wire_fixed_extents_and_immutable_reads`
- `smoke_coredump_execution_wire_lrc_ring_scratch_and_immutable_reads`
- `smoke_coredump_vm_wire_owned_tables_corruption_and_immutable_reads`
- `smoke_coredump_live_gt_capture_stop_and_authority_loss`
- `smoke_hardware_coredump_execution_timeout_snapshot_survives_full_reset`
- `smoke_hardware_vm_dump_retains_closed_user_bo_through_capture_and_full_reset`

### OA buffer mapping and the i915 OA timestamp frequency — native fixtures added

Sources are Linux b90c984d `xe_oa.c::xe_oa_mmap`, `mm/memory.c`
(`remap_pfn_range`), `mm/mmap.c::dup_mmap`, `mm/mremap.c::check_prep_vma`,
`i915_getparam.c` and `i915_perf.c::i915_perf_oa_timestamp_frequency`.

**The syscall-layer mapping.** `xe_oa_mmap` sets `VM_PFNMAP`,
`VM_DONTEXPAND`, `VM_DONTDUMP` and `VM_DONTCOPY`, clears `VM_MAYWRITE` and
`VM_MAYEXEC`, and then runs `remap_pfn_range` over the BO's pages. NARF's
syscall layer gained the matching mapping without a memory/ (TCB) change. A
file returns `Some(PrivatePfnMap { dont_copy })` from the new
`FileOps::mmap_private_pfn`. A `MAP_PRIVATE` request that passes the file's
`validate_mmap` is then mapped from `mmap_backing` as a borrowed, read-only
region. It keeps the usual owner row (file plus lifetime token), and nothing
is copied through `read()`. A provider whose request or `mmap_max_prot`
admits write or exec is refused with ENODEV, since there is no
copy-on-write over borrowed frames. The owner row keeps the flags across
splits and moves:

- mprotect cannot add write or exec (EACCES).
- mremap growth is EFAULT. DONTUNMAP and an `old_len` of 0 (a private
  duplicate) are EINVAL. Shrinking and same-size moves proceed.
- With `dont_copy`, memory's fork hook withholds the owner row from the
  child. `sys_fork` and the non-`CLONE_VM` clone then call
  `mapped_file::finish_fork_address_space`, which punches the range from
  the child's region copy before the child can run, as `dup_mmap` clears
  the VMA. The punch frees no borrowed frame.
- Shared futex keying treats the range as private.

**The OA buffer.** A request that passes the unchanged `xe_oa_mmap` checks
now maps the stream's first buffer-size pages of the unit's reservation
(16 MiB by default, grown up to 128 MiB) from the VMA start, write-back. As in the source, the offset is ignored.
`GpuBacking::host_frame` supplies the pages; only `FrameBacking` has them, so
model and device-local backings stay ENODEV. Each mapping holds a token on
the unit's page set. Because the mapping also holds the file, close(fd)
keeps the stream and its exclusive unit until munmap, as `vm_file` does.
Once the unit releases the reservation after a GT reset, suspend or
teardown, new mappings are ENODEV. A unit released while a token lives never
returns the reservation to its allocator. The reservation's GGTT range stays
quarantined, where Linux would keep the BO until the last VMA closes.

NARF gaps: `/proc/<pid>/maps` prints the range as shared (`s`), not `p`,
because the region uses borrowed-frame ownership. There is no `VM_DONTDUMP`
counterpart. madvise does not apply Linux's `VM_PFNMAP` refusals, such as
EINVAL for `MADV_DONTNEED`.

**GETPARAM 57.** `I915_PARAM_OA_TIMESTAMP_FREQUENCY` now returns
`i915_perf_oa_timestamp_frequency`: the CS reference clock, shifted by
RPM_CONFIG0's CTC shift on 12.55 and 12.70–12.74 (Wa_18013179988). As in
i915, it does not depend on i915 perf or the OA opt-in. The source reads
RPM_CONFIG0 on every call. NARF samples it once with the clock in
`DeviceFacts::oa_timestamp_frequency`, and both are ENODEV without published
facts. GETPARAM 54 (PERF_REVISION) stays 0 while PERF_OPEN is absent.

**Still open.** These remain as the previous subsection records:

- Media-GT OAM. It needs a media-GT OA unit with its own reservation, the
  OAM register block at the media GSI offset, a second query-8 unit, and
  privileged kernel LRI jobs on the media GuC, whose scheduler has no
  kernel-command submission yet.
- DRM_I915_PERF_OPEN, ADD_CONFIG, REMOVE_CONFIG and query item 3.

Fixtures:

- `smoke_abi_private_pfn_mmap_readonly_dontcopy_dontexpand` (new,
  `syscall_abi`). It drives `sys_mmap`, `mprotect`, `mremap`, fork
  completion, close, munmap and address-space teardown over a
  driver-shaped file.
- `smoke_oa_mmap_pages_hold_stream_and_survive_unit_release` (new). It
  covers the frames and offset rule, holds across close, reopen after the
  last unmap, and reset release with and without a live mapping.
- `smoke_oa_mmap_source_checks_then_private_pfn_backing`. This is the
  renamed `smoke_oa_mmap_source_checks_and_private_pfn_refusal`: a passing
  request now validates, and a backing without host pages is ENODEV at
  `mmap_backing`.
- `smoke_i915_observed_discovery_and_immutable_facts_after_loss` and
  `smoke_i915_discovery_missing_cross_platform_and_faulted_copies` now also
  cover GETPARAM 57.

### Display-14 PSR2 selective update and frame damage — native fixtures added

This slice adds PSR2 with selective fetch to the KMS-owned MTL/Arrow Pipe-A
eDP, and the frame damage that drives it. It supersedes the Remaining bullet
of "Display-14 PSR1 under KMS ownership". Sources are Linux b90c984d:
`intel_psr.c`, `intel_psr_regs.h`, `intel_alpm.c`,
`intel_dp_aux.c::intel_dp_aux_fw_sync_len`, `intel_quirks.c`,
`intel_display_device.c` (display stepping), `intel_display.c`,
`intel_crtc.c::intel_pipe_update_start`, `skl_universal_plane.c`,
`intel_cursor.c`, `intel_fbc.c`, `drm_framebuffer.c::drm_mode_dirtyfb_ioctl`,
`drm_damage_helper.c`, `drm_atomic_uapi.c` and `drm_property.c`.

**Damage.** DIRTYFB now checks in Linux's order: the request copy (EFAULT),
the master check (EACCES), the framebuffer lookup (ENOENT), the clip count
(EINVAL), then the clip copy (EFAULT). Unknown flag bits are masked, not
refused, so the existing fixture that expected a refusal now asserts the mask.
On the Intel KMS card the clips become the re-present's damage as
`drm_atomic_helper_dirtyfb` builds it: every second clip under ANNOTATE_COPY,
and no clips for the whole plane. i915 instead ignores the clips and flushes
the whole frontbuffer, but every Intel KMS change here is a commit, so the
helper's semantics apply. The Intel primary plane now carries
FB_DAMAGE_CLIPS. Its blob id is looked up as a u32, an unknown blob or a
length that is not whole `drm_mode_rect`s is EINVAL, and the property reads
back 0. A present merges the damage as `drm_atomic_helper_damage_merged`
does: clamped to the plane source, and the whole plane when the source moved.

**Qualification.** Once PSR1 qualifies, `compute_psr2` runs
`intel_sel_update_config_valid` for display 14 with Linux's defaults. The
sink must support SU and `pipe_bpp` must be at most 30. The IO and fast wake
lines come from `intel_alpm_compute_params`: 42 µs, or 44 µs under the
`QUIRK_FW_SYNC_LEN` laptop, at most 12 lines and at least 7. The PSR2
block-count lines must fit the vblank, then the SDP prior-scanline
indication (in Linux's u32 arithmetic) and `psr2_granularity_check` (display
14 keeps the sink's Y granularity), then the late vblank check. The live
facts are the `GMD_ID_DISPLAY` stepping, `PIPE_MISC`, `TRANS_DDI_FUNC_CTL`,
`TRANS_SET_CONTEXT_LATENCY`, the pipe DSS registers, the PCI identity and the
sink's trained link rate (`DP_LINK_BW_SET`, or the eDP 1.4 rate-select
table). A refusal is a typed `Psr2Refusal`, recorded on the owner, and PSR1
runs instead. Two choices are stricter than Linux. DSC, a joiner or the MSO
splitter refuses PSR2, because the slice alignment and Wa_14014971492 are not
modelled. The late check uses the live set context latency where Linux
computes 0.

**Enable and activation.** The sink gets `DP_RECEIVER_ALPM_CONFIG` (enable,
lock-error IRQ), then the PSR2 `DP_PSR_EN_CFG` (with SU-region scanline
capture when the indication is required), then `DP_SET_POWER` D0. Next comes
the qualifying commit's selective fetch over the whole plane, then the
source: `PSR_MASK`, `psr_irq_control`, Wa_14015648006 and, on display 14.00
A0..A3, Wa_16014451276 and Wa_16012604467. `hsw_activate_psr2` writes
`EDP_PSR_CTL` 0, then `EDP_PSR2_CTL` with the idle frames, frames before SU,
the VBT PSR2 TP2 time, the block count and the wake lines. Every refusal
precedes the first write. Disable clears PSR2, undoes the two A-step and
watermark workarounds, and clears the sink's PSR and ALPM configuration.

**Selective update.** The KMS worker runs a primary present in a selective
session, which leaves an active PSR2 running. The commit computes
`intel_psr2_sel_fetch_update`. The damage gives the SU rows, aligned to the
granularity. A failed calculation, a scaler or an unsupported cursor gives a
continuous full frame instead. Every visible plane that crosses the SU area
fetches its rows: always the primary, and the cursor when it crosses (its
fetch is disabled when it leaves). Without early transport the area is not
grown to the cursor. The primary's no-arm registers are written first, then
the PSR frame-change event, a `CURSURFLIVE` write. Linux uses that event on
its DSB path; its MMIO path relies on the vblank interrupt, which this driver
does not have. PSR2 then has 50 ms to leave deep sleep. On timeout Linux
proceeds; here PSR2 also exits, and the session end re-arms it.
`PSR2_MAN_TRK_CTL` and `SEL_FETCH_PLANE_CTL` precede the plane arm.
`SEL_FETCH_CUR_CTL`, with `CURBASE` rewritten unchanged, follows it. Single
full frame (`intel_psr_configure_full_frame_update`) is modelled but never
written, because no frontbuffer origin exists here.

**Everything else is unchanged.** Cursor, color, DSB, console and legacy
sessions and the external pass exit PSR2 and wait for its idle exactly as
for PSR1, and the guard re-arms it. FBC stays refused while PSR2 is enabled
("Selective update enabled"). DC handling is unchanged: PSR2 holds no DC_off
reference, and every conversation runs inside the session's.

**Remaining.** Panel Replay stays refused. Not covered: PSR2 with DSC, a
joiner or the splitter; early transport and DC3CO (display 20+, or disabled
in Linux); and hardware validation of the frame-change wake on display 14.

Fixtures:

- `drivers/gpu/drm/fb_legacy`: `dirtyfb_checks_follow_drm_mode_dirtyfb_ioctl_order`,
  `dirtyfb_damage_follows_drm_atomic_helper_dirtyfb` and
  `fb_damage_clips_blob_and_merge_follow_drm_damage_helper`.
- `drivers/gpu/intel_gpu_kms`: `intel_kms_dirtyfb_errnos_follow_drm_mode_dirtyfb_ioctl_order`,
  `intel_kms_dirtyfb_clips_become_the_present_damage`,
  `intel_kms_fb_damage_clips_validates_like_drm_atomic_set_property` and
  `intel_kms_commit_damage_reaches_the_display_owner`.
- `drivers/gpu/intel_gpu_psr`, register and sink models:
  `smoke_psr2_qualifies_like_intel_sel_update_config_valid`,
  `smoke_psr2_refusals_fall_back_with_typed_reasons`,
  `smoke_psr2_source_reads_the_live_pipe_and_link`,
  `smoke_psr2_ctl_and_sink_bytes_follow_hsw_activate_psr2`,
  `smoke_psr2_enable_programs_alpm_sink_then_sel_fetch_then_source`,
  `smoke_psr2_exit_resume_and_disable_use_the_psr2_registers`,
  `smoke_psr2_su_area_follows_intel_psr2_sel_fetch_update`,
  `smoke_psr2_cursor_joins_the_su_area_commit` and
  `smoke_psr2_sel_fetch_registers_follow_the_plane_and_cursor_arms`.
- `drivers/gpu/intel_gpu_psr`, the production `Device`/`Guard` path (x86_64):
  `smoke_psr2_kms_enables_selective_fetch_after_latch`,
  `smoke_psr2_kms_damaged_present_runs_a_selective_update`,
  `smoke_psr2_kms_deep_sleep_timeout_exits_before_the_arm`,
  `smoke_psr2_kms_cursor_joins_the_selective_fetch`,
  `smoke_psr2_kms_unqualified_falls_back_to_psr1_with_typed_reason`,
  `smoke_psr2_kms_external_pass_brackets_psr2` and
  `smoke_psr2_kms_fbc_stays_off_and_disable_precedes_console`.

Changed fixture: `dirtyfb_request_validation_and_damaged_rows_follow_linux`
expected an unknown DIRTYFB flag to be refused; it now asserts that Linux
masks it. The KMS mock treats a `CURSURFLIVE` write as the frame-change event
(read-only register, wakes a deep-sleeping PSR2), lets a cleared
`EDP_PSR2_ENABLE` idle the PSR2 status, and reports a PCI identity.

### Display-14 6 bpc pipes, eDP rate tables and display-13 TRANS_VBLANK — native fixtures added

This slice lets panels that need 6 bpc or an eDP rate table light, and
fixes one Gen12 register value. Sources are Linux b90c984d: `intel_dp.c`
(`intel_dp_compute_link_config`, `intel_dp_compute_link_config_wide`,
`intel_dp_compute_config_limits`, `intel_dp_max_bpp`,
`intel_edp_fixup_vbt_bpp`, `intel_edp_init_dpcd`,
`intel_edp_set_sink_rates`, `intel_dp_set_sink_rates`,
`intel_dp_compute_rate`, `intel_dp_rate_select`),
`intel_dp_link_training.c` (`intel_dp_prepare_link_train`,
`intel_dp_link_training_set_bw`,
`intel_dp_get_link_train_fallback_values`), `intel_display.c`
(`compute_baseline_pipe_bpp`, `compute_sink_pipe_bpp`,
`bdw_set_pipe_misc`, the `dither` decision,
`intel_set_transcoder_timings`), `intel_ddi.c`
(`intel_ddi_set_dp_msa`, `intel_ddi_read_func_ctl`), `drm_edid.c`
(`update_display_info`, `edid_quirk_list`), `drm_atomic.c`
(`drm_atomic_connector_check`) and `intel_display_device.c` (ADL-P and
ADL-N are display 13, TGL and ADL-S display 12).

**The pipe bpp.** The pipe's maximum is the EDID's `display_info.bpc`
(8 when undefined) capped at NARF's 8 bpc. On eDP a panel whose EDID has
no bpc takes the VBT's `edp.bpp` when it is lower, and a lit eDP
transcoder's bpp raises that VBT value, as `intel_edp_fixup_vbt_bpp`
does. The link search tries 24 bpp, then 18 bpp, each over the common
rates and lane counts, lowest rate first; only when neither fits is DSC
tried, with the same pipe maximum. A 6 bpc pipe dithers (`PIPE_MISC`
BPC_6 with DITHER_ENABLE), and writes `TRANS_DDI_FUNC_CTL` BPC_6, the
MSA's 6 bpc and `intel_link_compute_m_n` at 18 bpp. The typed refusal
`SixBpcUnqualified` is gone.

**The eDP panel.** The Pipe A modeset now runs the decision for every
panel whose caps it can read, with the EDID bpc it caches from its EDID
read. When 24 bpp fits and the panel has no rate table, the existing
sequence runs byte for byte. It only reads `PIPE_MISC`, and rewrites it
and the MSA to 8 bpc when an earlier 6 bpc modeset or firmware left a
6 bpc or dithered pipe. A 6 bpc panel, or one that publishes
`DP_SUPPORTED_LINK_RATES`, takes Linux's link, eDP intermediate rates
included, on the C10 eDP PLL. A rate-table panel trains with
`DP_LANE_COUNT_SET` and `DP_LINK_RATE_SET` at the rate's table index,
after re-reading the table (WaEdpLinkRateDataReload), and never sees
`DP_LINK_BW_SET`. This path trains one configuration. When it fails on
a panel not already at its maximum parameters, the modeset retries once
there, as Linux sets `use_max_params` for eDP. A panel whose link carries
neither bpp and that cannot decompress now refuses `SinkUnsupported`
before any write, where it used to try 24 bpp anyway. An eDP 1.4 DSC
panel with a rate table also trains its DSC link with `DP_LINK_RATE_SET`.

**External DP.** A sink whose EDID caps the pipe at 6 bpc, or whose link
carries only 18 bpp, runs a 6 bpc route on Linux's link. The Pipes owner
writes the dithered `PIPE_MISC` from `ExternalPipe::pipe_bpp`. The route
writes the 6 bpc MSA after the normal pattern, and its stop leaves an
8 bpc MSA behind. The 8 bpc route is unchanged.

**TRANS_VBLANK on display 13.** The Gen12 orchestrator now writes
`TRANS_VBLANK` with VBLANK_END only on ADL-P and ADL-N, as Linux does on
display 13+. TGL, ADL-S and a modeset without a known family keep the
display-12 value. This is a Gen12-family behaviour change. The Gen12 DSB
timing proof compared the whole register, so the DSB owner now takes a
display-13 flag from the KMS family and proves only VBLANK_END there; TGL
keeps the full proof.

Remaining: a production caller of the panel fitter, which
`XeLpgModeset::with_panel_fit` plumbs through the modeset. Also open: Gen12 eDP rate-table panels still
train with `DP_LINK_BW_SET`; the VBT 263+ `edp_data_rate_override` and the
`QUIRK_EDP_LIMIT_RATE_HBR2` platform quirk do not filter the sink rates; a
VBT that picks its panel by PnP ID gives no `edp.bpp` clamp; branch
devices' downstream bpc limits (`dfp.max_bpc`) are not read; the link
fallback stops after the maximum-parameter retry instead of reducing the
link; the 8 bpc external route still writes no MSA; the XR30 admission
keeps requiring an 8 bpc route; the EDID bpc is known only after the
modeset has read the panel's EDID once; ADL's `TRANS_SET_CONTEXT_LATENCY`
is not written. Physical Intel acceptance is open.

Fixtures:

- `drivers/gpu/intel_gpu_xelpg_dsc`:
  `smoke_xelpg_dsc_edid_bpc_follows_update_display_info`,
  `smoke_xelpg_dsc_six_bpc_pipe_bpp_and_register_values` and
  `smoke_xelpg_dsc_edp_vbt_bpp_clamp_rate_table_and_fixup`.
- `drivers/gpu/intel_gpu_modeset_xelpg`:
  `smoke_mtl_edp_six_bpc_programs_pipe_misc_ddi_msa_and_mn`,
  `smoke_mtl_edp_rate_table_trains_with_link_rate_set`,
  `smoke_mtl_edp_planned_link_retries_at_max_params`,
  `smoke_mtl_edp_eight_bpc_keeps_write_stream_and_clears_stale_six_bpc`
  and `smoke_mtl_edp_vbt_bpp_clamp_and_lit_pipe_fixup`.
- `drivers/gpu/intel_gpu_xelpg_external`:
  `smoke_mtl_external_dp_six_bpc_route_from_edid_bpc`.
- `drivers/gpu/intel_gpu_modeset`:
  `smoke_program_transcoder_vblank_start_follows_display_version`;
  `drivers/gpu/intel_gpu_dsb`:
  `smoke_dsb_display13_gen12_timing_proves_vblank_end_only`.

Changed fixtures: `MtlFake` models a valid eDP receiver (DPCD 1.2, HBR2
x4), because every readable panel now runs the decision and Linux falls
back to RBR x1 for the all-zero DPCD; its 24 bpp fixtures keep their
sequences, and it gains a `cr_fails_at` sink knob. Decision smokes that
pinned `SixBpcUnqualified` now pin the 18 bpp link Linux picks, and the
eDP 1.3 OLED on HBR2 x2 now refuses `SinkUnsupported`. The modeset
refusal smoke's 6 bpc slot now pins the VBT's 18 bpp leaving DSC no input
range (`NoBppRange`). The external DSC refusal smoke's two-lane case now
lights at 6 bpc. Existing DSB smokes pass the flag that keeps their
previous proof.

### Display-14 panel off and on, and the eDP link-training fallback — native fixtures added

The sources are Linux b90c984d: `intel_display.c` (`intel_atomic_commit_tail`,
`intel_pre_plane_update`, `intel_commit_modeset_disables`,
`intel_crtc_disable_planes`, `hsw_crtc_disable`), `intel_ddi.c`
(`intel_ddi_disable_dp`, `intel_ddi_post_disable_hdmi_or_sst`,
`intel_ddi_post_disable_dp`, `intel_ddi_buf_disable`,
`intel_ddi_disable_transcoder_func`, `intel_ddi_disable_transcoder_clock`,
`mtl_ddi_pre_enable_dp`, `mtl_ddi_prepare_link_retrain`,
`intel_ddi_init_dp_buf_reg`), `intel_pps.c` (`intel_pps_off_unlocked`,
`intel_pps_on_unlocked`), `intel_dp_link_training.c`
(`intel_dp_get_link_train_fallback_values`,
`reduce_link_params_in_rate_lane_order`,
`intel_dp_can_link_train_fallback_for_edp`), `drm_client_modeset.c`
(`drm_client_modeset_dpms`), `drm_fb_helper.c` (`drm_fb_helper_blank`) and
`fb_chrdev.c` (`do_fb_ioctl`).

**Panel off.** `XeLpgModeset::disable_planes` and `XeLpgModeset::panel_off`
are the crtc disable for the owned eDP on DDI A and Pipe A. The KMS owner
first restores the console and disables PSR and FBC. The planes go off,
then the DPCD backlight owner disables the backlight and closes the PPS gate,
and T9 is waited without spinning. Then come the sink's decompression, the
transcoder, `TRANS_DDI_FUNC_CTL2` and the function, the VDSC engines, the PPS
SDP, `DP_SET_POWER` D3, `DDI_CTL_DE` with the PHY idle, D2D and `DP_TP_CTL`,
`TRANS_CLK_SEL`, VDD on and the single `PP_CONTROL` write of
`intel_pps_off`, the port PLL (`intel_cx0pll_disable`) and the Thunderbolt
IO deselect. Last comes the pipe DMC disable, which drops the panel's display
wakeref. With no other pipe lit, the post-plane all-off settle lowers WM/DDB,
DBUF, CDCLK and PM demand. A record keeps the mode and the
`DDI_BUF_CTL` reversal bit for the panel-on.

**Panel on.** The owned modeset takes the full `mtl_ddi_pre_enable_dp` when
the record names its port and the hardware is off: VDD for the planning AUX
reads, `intel_pps_on` after the pipe DMC enable and before the PLL,
`TRANS_DDI_FUNC_CTL` configured without ENABLE, `DDI_CTL_DE` and the buffer
active between TPS1 and the training, and the function enabled just before
the transcoder. The existing sequence otherwise runs unchanged. The
production path is the system-resume relight: the DPCD owner powers the
panel with its gate closed, the modeset lights the console surface, and the
owner relights the backlight after T8.

**Producers.** An atomic `ACTIVE=0` or `SETCRTC` off from the master turns
the panel off after the console restore and the event's vblank. Lighting the
crtc again (a presented frame, or an observe on a dark panel) runs the
panel-on first. `DROP_MASTER` and the last close relight it, as the fbdev
restore commits the console active. `FBIOBLANK` maps the blank levels as
`drm_fb_helper_blank` does: `EINVAL` above 4, UNBLANK lights the panel and
every other level turns it off; with a KMS master nothing changes, and the
ioctl returns 0. The KMS session takes `intel_display_rpm_get` first, so a
commit resumes an autosuspended function. With the panel dark, the park
admission sees nothing lit and the function autosuspends after its delay. A
runtime resume brings the GT back, and the panel stays off until a producer
lights it.

**Beside a lit external.** Nothing of Pipes B–D, their transcoders, ports or
the shared layout is written. Pipe A's DDB/WM share stays programmed, and PM
demand and CDCLK keep covering it. Linux would repartition the external into
it. The Pipe B–D owner now reads Pipe A's lit bit from the hardware before
each transition, so a dark panel is a reserved, unlit pipe in its layout.
Lighting the panel again beside a lit external needs Pipe A's share proved
(`Profile::capture`). Otherwise it refuses `DisplayResourceUnavailable`
before the PLL, the DDI or the transcoder, and drops VDD.

**Fallback ladder.** `LinkLimits::fallback` is
`intel_dp_get_link_train_fallback_values`. eDP first takes
`use_max_params`. Then the rate steps down the common rates at the same
lanes. At the lowest rate the lanes halve and the rate returns to the
maximum. An eDP panel whose fixed mode at 18 bpp no longer fits the reduced
link keeps its parameters for one more attempt. The panel's planned link
(6 bpc or rate-table panels) walks it, each step recomputing the link
(`decide_edp_capped`) and moving the PLL, lanes, port width and function. A
step that would change the pipe bpp or need DSC refuses
`Dsc(TrainingFallback)`; an exhausted ladder refuses
`ModesetError::LinkTrainingExhausted`. Behaviour change: a panel that failed
its maximum-parameter retry used to fail the modeset, and now steps down.

Remaining: the external DP route still uses the shared training's internal
ladder and one modeset retry, not this one, and its PM demand and M/N are
not recomputed per step. Lighting the panel beside a lit external whose
layout lacks Pipe A's share (an external activated while the panel was dark)
is refused; adding Pipe A to a live layout is not implemented. The KMS
surfaces retire through one console frame before the off. A cursor on the
dark crtc is accepted and not retained. No connector `DPMS` property is
exposed. Gen12 has no panel-off producer: its conversations need wakerefs
and its PWM backlight a park. The 8 bpc legacy eDP sequence keeps its
existing order (D2D and levels before TPS1). Gen12 eDP `DP_LINK_RATE_SET`
training is not added. None of this is physical Intel evidence.

Native fixtures:

- `drivers/gpu/intel_gpu_modeset_xelpg`:
  `smoke_mtl_panel_off_follows_hsw_crtc_disable_order`,
  `smoke_mtl_panel_on_after_off_runs_full_enable_and_restores_image`,
  `smoke_mtl_panel_off_beside_lit_pipe_b_writes_only_the_panel` and
  `smoke_link_fallback_ladder_follows_rate_lane_order`.
- `drivers/gpu/intel_gpu_power`:
  `smoke_display_rpm_panel_off_parks_and_resume_keeps_the_panel_dark`.
- `drivers/gpu/intel_gpu_kms`:
  `intel_kms_active_off_turns_the_panel_off_and_master_release_relights`
  and `intel_kms_present_on_a_dark_panel_lights_it_first`.
- `drivers/gpu/intel_gpu_psr`:
  `smoke_kms_mtl_panel_off_disables_psr_first_and_refuses_unlatched_flip`
  and `smoke_kms_mtl_console_dpms_follows_master_and_toggles_the_panel`.
- `fb`: `smoke_fbdev_blank_levels_map_as_drm_fb_helper_blank`.

Changed fixture: `smoke_mtl_edp_planned_link_retries_at_max_params` asserted
that a failure at the maximum parameters failed the modeset. It now asserts
that the ladder reaches HBR x4, and that a sink failing every link walks
rate, then lanes, to `LinkTrainingExhausted`.

### Lunar Lake display 20 (Xe2_LPD) — native fixtures added

This slice starts the display part of the Additional platforms workstream.
Lunar Lake's display 20.00 now has an owned eDP Pipe-A modeset. The
display-14 chain is dispatched on a typed display IP instead of copied
(§17, 10.5). The modeset is reached only through an opted-in, read-only
per-device route (`narf.intel.lnl_display=1`). Every other Lunar Lake
function keeps the headless main-GT profile, and that profile's driver FLR
is never run on a display-owning function.

What changed, by file. `intel_gpu_xe2lpd` (new) holds the GMD decode, the
route, `XE2LPD_DE_CAP`, the CDCLK table, the MDCLK-ratio,
DBUF/MBUS/DBOX and package-C values, the PICA well model, the display-20
D2D link and the pipe-DMC flip-queue and interrupt programming. The
display-14 files gained version dispatch: `intel_gpu_xelpg_cdclk` `_ip`
variants; `intel_gpu_xelpg_resources` `compute_ip`, `State::ip` and the
IP-aware DBUF/MBUS/DBOX images, ratio ordering and restoration;
`intel_gpu_display_resources` IP reads, no no-DPT chicken on display 20 and
the running-clock proof; `intel_gpu_modeset_xelpg::with_display_ip`;
`intel_gpu_dmc` `DmcPlatform::Xe2Lpd`; and probe routing in `intel_gpu`.
Display-14 register conversations are unchanged: no display-14 path gains
a read or a write.

What a real Lunar Lake would complete, opted in, with GOP lighting the
panel: route admission, panel power sequencing, EDID, the display-20
resource transaction (PM demand, CDCLK, MDCLK ratio, DBUF, MBUS,
watermarks), the C10 port PLL, link training on DDI A, the transcoder and
primary enable on the firmware surface and the package-C latency. The
console keeps drawing on that surface. Nothing past that runs: no KMS or
DRM flips (no GT owner, no Xe2 scanout PAT policy), no DMC load or
DC5/DC6, no PSR or FBC, no backlight PWM or VBT, and no external outputs.
None of this has run on silicon.

Fixtures:

- `drivers/gpu/intel_gpu_xe2lpd`:
  `smoke_xe2lpd_gmd_decode_and_typed_refusals`,
  `smoke_xe2lpd_route_is_read_only_and_keeps_headless_otherwise`,
  `smoke_xe2lpd_source_facts`, `smoke_xe2lpd_cdclk_table_decode_and_ctl`,
  `smoke_xe2lpd_cdclk_plan_squash_crawl_midpoints`,
  `smoke_xe2lpd_mdclk_ratio_dbuf_mbus_and_dbox`,
  `smoke_xe2lpd_pkgc_latency` and `smoke_xe2lpd_pica_well_and_d2d_link`.
- `drivers/gpu/intel_gpu_xe2lpd_resources`:
  `smoke_xe2lpd_resources_compute_dispatch_keeps_display14`.
- `drivers/gpu/intel_gpu_xe2lpd_modeset`:
  `smoke_xe2lpd_owned_modeset_lights_pipe_a_with_display20_resources`,
  `smoke_xe2lpd_owned_modeset_lowers_known_clock_ratio_first`,
  `smoke_xe2lpd_owned_modeset_failure_restores_clock_and_ratio`,
  `smoke_xe2lpd_raising_floor_programs_ratio_after_clock` and
  `smoke_xe2lpd_entry_refuses_without_display20_read_only`.
- `drivers/gpu/intel_gpu_xe2lpd_dmc`:
  `smoke_xe2lpd_dmc_parse_ceiling_and_load_order` and
  `smoke_xe2lpd_pipe_dmc_flip_queue_and_interrupts`.

The display-preserving Lunar Lake GT/KMS owner, display-20 resource profile,
FBC count, PSR1 deltas and TC1–TC4 Type-C/PICA external route described by
this workstream are implemented, as are DP and HDMI TMDS on combo DDI B (and
HDMI on declared legacy Type-C ports) through the display-20 D2D/DDI_BUF_CTL
programming. Remaining output work includes UHBR. Panther Lake's additional
display-30 deltas are recorded in
`intel_gpu_xe3lpd`.

### Lunar Lake display 20: GT owner, KMS flips and DC6 — native fixtures added

This slice continues the Lunar Lake display-20 route (§17, 10.5). Everything
stays behind `narf.intel.lnl_display=1`, and every Lunar Lake function
without the route keeps the headless main-GT profile and its driver FLR
unchanged.

The route's function now has a GT owner. Linux xe never runs a driver FLR at
probe; it makes a GT fresh with the GuC reset and, on reset and shutdown,
`do_gt_reset`'s `GRDOM_FULL`, while display keeps running. NARF's GT
bring-up already issues that pair on the primary and media GTs before its
first GGTT PTE, so the display-preserving profile replaces only the FLR. A
read-only admission proves no FLR is in flight, display 20.00 with Pipe A
lit, and no inherited display DMA outside the route's primary. It clears one
stale FLR status bit so that any later FLR fails every PTE write. The
profile refuses system suspend, because display-20 relight is not owned.

Probe then moves the console onto an owned surface mapped at the firmware
surface's own PAT index, which must be 0, and installs the KMS owner for
display 20. Linear fixed-mode Pipe-A flips map GEM pages with Xe2 PAT3, the
uncached display index of Linux xe, admitted only once the GT owner has
programmed it. The owner keeps the display-20 pipe status bits, the FBC A–D
and five-plane fetcher inventory, and the LNL dummy-write workaround before
every read. Console restoration and GT-reset recovery run through the
existing owner. The DC service also runs on display 20: after GT
publication it loads `xe2lpd_dmc.bin` under the display-20 rules, enables
Pipe A's DMC and enters DC6. PSR1 stays refused, with its display-20 deltas
recorded in §17. The cursor, color, DSB transactions, tiled primaries and FBC
are not offered yet.

What a real Lunar Lake would do, opted in, beyond the previous slice: start
its GT (GuC, engines, private VMs and the startup execution proofs) beside
the lit panel and publish render/compute to userspace, move the console to
the owned surface, flip linear WC framebuffers on Pipe A, and enter DC6
when idle if `xe2lpd_dmc.bin` is present. None of this has run on silicon.

Fixtures:

- `drivers/gpu/intel_gpu_xe2lpd_gt`:
  `smoke_xe2lpd_gt_display_admission_reads_display_only_and_never_flrs`,
  `smoke_xe2lpd_gt_hardware_init_resets_gt_only` and
  `smoke_xe2lpd_gt_profile_selection_keeps_headless_flr`.
- `drivers/gpu/intel_gpu_xe2lpd_kms`:
  `smoke_xe2lpd_kms_pte_profile_and_owned_status`,
  `smoke_xe2lpd_kms_linear_flip_maps_pat3_and_restores_console`,
  `smoke_xe2lpd_kms_fetcher_inventory_and_refused_services` and
  `smoke_xe2lpd_kms_psr1_refused_on_display20`.
- `drivers/gpu/intel_gpu_xe2lpd_dc`:
  `smoke_xe2lpd_dc_service_profile_and_firmware` and
  `smoke_xe2lpd_dc_service_loads_xe2lpd_dmc_and_enters_dc6`.

Remaining for the workstream, in order: the cursor and DSB owners' display
PTE profile (their GGTT pages still use the display-14 format and PAT1),
then cursor, color and DSB on display 20; the Xe `SCANOUT` create flag on
the display profile; Wa_15015404425 on the route's probe-time modeset
window; display-20 relight and suspend; PSR1's display-20 deltas; FBC on the
HDR planes; and Type-C/PICA externals.

### Lunar Lake display 20: cursor, color, DSB, tiled primaries and SCANOUT — native fixtures added

This slice continues the Lunar Lake display-20 route (§17, 10.5), still only
behind `narf.intel.lnl_display=1`. It closes the first four items the
previous slice left.

The cursor and DSB owners now map their pages with the IP's display GGTT
profile: Xe2 PTEs at PAT3, admitted only while the GT owner's
`PAT_INDEX(3)` reads 0x3c. With that, the KMS owner offers the display-14
cursor, CTM, gamma and degamma LUTs and DSB transactions on display 20.
intel_cursor.c, intel_dsb.c and intel_color.c have no branch between
displays 14 and 20 at the pinned revision, so the register conversations
are unchanged. The cursor's fault mask is the display-20 one, without the
PIPEDMC faults.

X and Tile4 primaries are now owned on display 20. Display 20 has no
no-DPT chicken, so the presenter builds a display page table for each
tiled surface, laid out like Linux's power-of-two remap, and maps it at a
2 MiB-aligned GGTT address that `PLANE_SURF` names. Only a source stride
that fits the DPT stride is owned, and panning a tiled primary is refused.
Tiled admission reads no new display-14 register. Display 14 still checks
its chicken; display 20 skips it.

The Xe `SCANOUT` create flag is admitted on the display-preserving
profile as xe takes it, a WC system object marked for scanout. The
route's probe-time modeset window, panel power sequencing through the
backlight gate, now applies Wa_15015404425 like the rest of the display-20
paths.

Meteor Lake and Gen12 register conversations are unchanged. Two existing
display-20 fixtures assert the new contract: the cursor is refused before
any write without a proved display-20 layout, and an X-tiled display-20
primary proves the linear watermark image.

What a real Lunar Lake would do, opted in, beyond the previous slice:
create scanout objects with the Xe flag, draw a hardware cursor, apply CTM
and gamma/degamma LUTs (through the DSB when active), and flip X/Tile4
framebuffers through the owned DPT. None of this has run on silicon.

Fixtures:

- `drivers/gpu/intel_gpu_xe2lpd_kms`:
  `smoke_xe2lpd_kms_cursor_and_dsb_pages_map_xe2_pat3`,
  `smoke_xe2lpd_kms_cursor_fault_mask_drops_pipedmc`,
  `smoke_xe2lpd_kms_cursor_arms_through_dsb_on_display20`,
  `smoke_xe2lpd_kms_ctm_and_gamma_owned_on_display20`,
  `smoke_xe2lpd_kms_dpt_layout_pot_remap` and
  `smoke_xe2lpd_kms_tile4_flips_through_owned_dpt`.
- `drivers/gpu/intel_gpu_xe2lpd_gt`:
  `smoke_xe2lpd_gt_scanout_create_flag_follows_display_profile`.
- `drivers/gpu/intel_gpu_xe2lpd_modeset`:
  `smoke_xe2lpd_probe_window_flushes_every_read`.

Remaining for the workstream, in order: display-20 suspend and relight
(display power and DMC restore, the GT owner's resume without an FLR and
the KMS restore); PSR1's display-20 deltas, recorded in §17; FBC on display
20; panning of a tiled display-20 primary; and Type-C/PICA externals.

### i915 context priority through GuC registration — native fixtures added

Sources are Linux b90c984d `intel_guc_submission.c`
(`map_i915_prio_to_guc_prio`, `guc_context_init`, `add_to_context`,
`update_context_prio`, `guc_context_set_prio`, `__guc_context_set_prio`,
`guc_bump_inflight_request_prio`, `guc_context_policy_init_v70`),
`intel_guc_fwif.h`, `i915_priolist_types.h`, `i915_gem_context.c`
(`proto_context_create`, `validate_priority`, `set_priority`,
`set_proto_ctx_param`, `setparam_ioctl`), `i915_request.c` and
`i915_scheduler.c::__i915_schedule`.

**Behaviour change on real hardware.** Every i915 compatibility context used
to register with GuC priority 3 (GUC_CLIENT_PRIORITY_NORMAL), below Linux's
default. Each hardware member now registers at `map_i915_prio_to_guc_prio`
of its context's priority, so a default context is KMD_NORMAL (2), as in
Linux. Negative priorities give NORMAL (3), positive ones HIGH (1); KMD_HIGH
(0) needs I915_PRIORITY_DISPLAY and stays unreachable from userspace. Native
Xe queues keep their own LOW3/NORMAL2/HIGH1 mapping, which already matches
`xe_exec_queue_prio_to_guc`.

**Live priority.** A PRIORITY set on a proto or finalized context stores the
priority, as Linux's does, and sends GuC nothing. Each execbuffer is a
request queued at the context's priority at its ioctl (rq->sched.attr) and
counted per band until its claim, like `ce->guc_state.prio_count`. A request
raises, and never lowers, the job ahead of it on the same hardware context
(`__i915_schedule` and `guc_bump_inflight_request_prio`). The scheduler
follows `guc_context_set_prio`:

- A raise before the job's Policy request is stored, and the registration
  carries it.
- A raise while the registration is enabled (Enable through Running) sends
  one priority-only UPDATE_CONTEXT_POLICIES (0x100b, SCHEDULING_PRIORITY
  KLV 0x20030001), as `__guc_context_set_prio` does for GuC 1.x.
- A job being disabled, timed out or reset gets no update. NARF's
  registration ends with each job.
- A queued request registers at its own band, raised by the requests still
  queued behind it.

`UserContext::configure_schedule` no longer returns EBUSY for a claimed
context. Its policy applies from the next registration; a job in flight keeps
the policy it was claimed with.

**UAPI.** GETPARAM HAS_SCHEDULER (41) reports ENABLED | PRIORITY (3) while
submission is live and 0 otherwise. PRIORITY sets follow `validate_priority`:
size EINVAL, then the capability (ENODEV only without a live owner), the
-1023..=1023 s64 range EINVAL, and EPERM above 0 without CAP_SYS_NICE, which
is asked only for an in-range positive value. SET looks the context up
(ENOENT) before any capability question; before this change a size-0
BANNABLE clear on a missing context asked CAP_SYS_ADMIN first.

LINUX-GAP: only requests on the same hardware context raise a job. Linux's
priority inheritance through object and fence dependencies on other
contexts' requests is not modelled.

Fixtures:

- `smoke_i915_priority_maps_to_guc_client_bands`
- `smoke_userspace_priority_update_follows_guc_context_set_prio`
- `smoke_i915_priority_default_contexts_register_kmd_normal`
- `smoke_i915_priority_bands_apply_at_the_next_registration`
- `smoke_i915_priority_lazy_gen12_media_member_takes_the_context_band`
- `smoke_i915_priority_raise_reaches_the_registered_job_through_the_next_request`

Changed fixtures:

- `smoke_i915_context_params_follow_set_proto_ctx_param_and_ctx_setparam`
  pinned ENODEV for every in-size PRIORITY set and GETPARAM 41 = 1; it now
  checks the full `validate_priority` order with and without CAP_SYS_NICE,
  the lookup before capable(), and GETPARAM 41 = 3.
- `smoke_i915_observed_discovery_and_immutable_facts_after_loss` and
  `smoke_i915_xe_exact_dispatch_discovery_sseu_and_wc_refusal` assert
  GETPARAM 41 = 3 while live.
- The `intel_gpu_i915_low_latency_tests.rs` policy decoder asserted the old
  priority 3 for every default i915 registration and now asserts 2.
- The GuC model accepts a 4-word priority-only UPDATE_CONTEXT_POLICIES only
  for a registered context, and records it.

### Xe MAP_USERPTR invalidation over memory/ interval notifiers — native fixtures added

Sources are Linux b90c984d: `mm/mmu_notifier.c` (the interval API),
`xe_userptr.c` (`xe_userptr_setup`, `vma_userptr_invalidate`,
`xe_vm_userptr_pin`, `__xe_vm_userptr_needs_repin`), `xe_exec.c`
(`xe_exec_ioctl`'s pin and `-EAGAIN` retry), `xe_vm.c::new_vma` and
`drm_gpusvm.c::drm_gpusvm_get_pages`. This is TCB-class work: the
notifier is new memory/ code (`memory/specification/spec.md` §3 and §4).

**Memory layer.** `narf_memory::mmu_notifier::MmuIntervalNotifier::insert`
registers `[start, start + length)` of one address space. Each operation
that changes the frame a VA translates to, or removes READ/WRITE, calls the
registry while it still holds the lock that serializes the change and before
it frees anything. That covers munmap/MAP_FIXED/brk shrink, mremap and
MREMAP_DONTUNMAP sources, truncate zaps, MADV_DONTNEED and GUARD_INSTALL, COW
breaks, swap-out, lazy-free discard, mprotect downgrades, migration, the OOM
reaper, exit and final drop. The registry stores a fresh odd sequence before
calling the consumer, so the Linux `read_begin`/`read_retry` protocol holds;
pins take the same lock, so `read_begin` need not wait. Callbacks are
non-blocking (`blockable()` is always false). The lock order is mapping
locks, then a registry shard, then the consumer's leaf lock, and nothing in
the registry takes a mapping lock.

**Consumer.** Bind registers the interval before pinning and repeats a
collection that an invalidation raced; eight raced rounds are ENOMEM at bind
and EBUSY at EXEC, as in Linux. EXEC
compares each binding's pin sequence and re-collects every slice of an
invalidated binding over its own CPU range under a fresh interval. It
rebuilds the job if a binding goes stale before submission. A slice whose
range is gone (EFAULT, or the binder exited) is dropped from the VM, and the
exec proceeds with that range unmapped or on scratch, as Linux invalidates
the VMA. EPERM (a writable binding over memory made read-only), ENOMEM and EBUSY
fail the exec; the binding stays invalidated, and the next EXEC retries.

**Deviations, with the safety argument.** Linux's `vma_userptr_invalidate`
waits for the VM's bookkeeping fences because HMM pages are not pinned. NARF
invokes callbacks under IRQ-masked mapping locks, where waiting for a GPU
job could deadlock the mm. The callback therefore does no work. The
snapshot-pin invariant is kept: every job holds the pins it was built with
until it retires, so the GPU never reaches a frame that was released or
reused. The notifier adds that no job built after the invalidation uses the
old pins. A job submitted before an unmap returns may still finish against
the retained old frames afterwards. Only the binder's own address space can
re-collect: another process's EXEC on a shared VM is ENOSYS, where Linux
pins through the binder's mm. An address + length overflow stays EFAULT
(Linux: -EOVERFLOW). The memory/ swap-out batch, lazy-free discard and
multi-owner compaction (`migrate_frame_multi`) used to move or drop a pinned
page while the GPU still wrote through the pin. They now refuse pinned
pages as Linux does (`folio_maybe_dma_pinned`); see the follow-up subsection
below.

**VRAM CPU-mapping revocation** (revoke a device-frame set, then refault after
runtime resume) was not part of this slice. It landed later; see "VRAM CPU
mappings across runtime suspend" below.

Fixtures:

- `memory`: `smoke_mmu_notifier_registration_range_filter_and_removal`,
  `smoke_mmu_notifier_sorted_scan_and_per_space_cap`,
  `smoke_mmu_notifier_seq_read_begin_retry_protocol`,
  `smoke_mmu_notifier_fires_for_each_mapping_operation`,
  `smoke_mmu_notifier_invalidates_before_frame_release`,
  `smoke_mmu_notifier_fork_cow_break_and_child_isolation`,
  `smoke_mmu_notifier_exit_and_drop_release_intervals`,
  `smoke_mmu_notifier_racing_reader_every_interleaving` and, on x86_64,
  `smoke_mmu_notifier_migration_refuses_pins_and_fires_on_move` and
  `smoke_mmu_notifier_lazyfree_discard_fires_clear`.
- `drivers/gpu/intel_gpu_user`:
  `smoke_xe_userptr_invalidation_repins_zaps_and_refuses`. Its `Cpu`
  fixture now models the process's VMAs in a real `AddressSpace`, so
  munmap, mprotect and MADV_DONTNEED on it fire the production notifier
  path. The existing `smoke_xe_userptr_bind_exec_validation_and_retirement`
  keeps its expectations.

### Pinned USERPTR pages survive reclaim — native fixtures added

Sources are Linux b90c984d: `mm/vmscan.c::shrink_folio_list` (the two
`folio_maybe_dma_pinned` tests), `mm/rmap.c::try_to_unmap_one` (the MADV_FREE
reference test and the anon-exclusive `folio_try_share_anon_rmap_pte`
back-off), `mm/rmap.c::try_to_migrate_one`, `mm/migrate.c` and
`mm/gup.c::follow_page_pte` (`FOLL_TOUCH` dirtying at a `FOLL_WRITE` pin).
This is TCB-class memory/ work (`memory/specification/spec.md` §3 and §4).

The frames behind an Xe MAP_USERPTR (or any other `UserPagePin`) were never
freed under the GPU, because the pin holds a reference. Their contents could
still diverge from the mapping: swap-out wrote a snapshot and repointed the
VA at a swap entry, lazy-free discard dropped a page the GPU had written
(device writes never set the PTE's DIRTY bit), and multi-owner compaction
repointed both COW owners at a copy. Each path now refuses a pinned page,
deciding under the region lock that pins are taken under:

- Swap-out skips pinned pages at selection and swaps the rest of the batch.
  A pin that lands after the PTE commit refuses that victim at publication.
  Its leaf is restored exactly, its slot is released and no `Clear` fires
  for it. The reclaim scan never offers a pinned page.
- `MADV_FREE` does not mark a pinned page, pinning drops an existing mark,
  and discard keeps a pinned page and clears its mark. Linux relies on the
  pinner dirtying the folio instead; NARF pins carry no dirty bit.
- `migrate_frame` reports the new `MigrateError::Pinned` for a pinned frame,
  and each owner's repoint rechecks the pin before it moves.

The paths are x86_64-only (aarch64 has no swap PTEs, and its `MADV_FREE` is
eager). Fixtures:
`memory::smoke_dma_pin_swap_out_skips_pinned_page`,
`smoke_dma_pin_swap_commit_refuses_racing_pin` (a kernel-test seam lands the
pin between commit and publication),
`smoke_dma_pin_lazyfree_never_discards_pinned_page` and
`memory/migrate::smoke_migrate_frame_multi_refuses_pinned`.

### VRAM CPU mappings across runtime suspend — native fixtures added

Sources are Linux b90c984d: `ttm_bo_vm.c` (`ttm_bo_unmap_virtual`,
`ttm_bo_vm_fault_reserved`), `mm/memory.c::unmap_mapping_range`, `xe_bo.c`
(`xe_bo_cpu_fault`, `__xe_bo_cpu_fault`, `xe_bo_runtime_pm_release_mmap_offset`,
the `vram_userfault` list) and `xe_pm.c::xe_pm_runtime_suspend`. The memory/
half is TCB-class (`memory/specification/spec.md` §3 and §4).

A discrete GT used to refuse runtime suspend while any VRAM was allocated,
because user CPU mappings of the LMEM BAR could not be revoked and the BAR
does not decode outside D0. Park now does what xe does:

1. It closes the pool to kernel CPU access (`Vram::close_cpu_access`, refused
   while a copy is in flight). GEM PREAD/PWRITE through the BAR then fail
   with `Busy`. The async i915 copy path takes a runtime-PM wakeref first
   (`UserBackend::cpu_vram_wakeref`), so it resumes the function instead.
2. It revokes the BAR window `[bar, bar + tile_offset + visible)` with
   `memory::revoke_device_frames`, through `mmap_relocation::revoke` and the
   syscall layer's address-space snapshot. Every user leaf goes, every VMA
   and alias stays, and the TLB invalidation completes before park continues.
   The Intel alias registry reports its census from inside the VM
   transaction. While the revocation lives, mappings made meanwhile (mmap,
   fork children, mprotect) stay unmapped too. A fork in flight or an unseen
   alias refuses the park with `Busy`, and the PM core retries.
3. It stops the GT as before. Any refusal before D3 reopens both.

A CPU access to a revoked page faults into `VramRefault`
(`__xe_bo_cpu_fault`). With no address-space lock held, the syscall layer's
waiter parks the faulting task on a future that takes a runtime-PM reference
(resuming the function) and waits for the resumed GT's publication. That
publication drops the revocation and reopens kernel access before `Running`
becomes observable, so the retried access maps the same BAR frame. A failed
resume, or an owner that is gone, is SIGBUS (xe: `VM_FAULT_SIGBUS` for a lost
device). Local memory itself is preserved across D3hot, as the pool already
assumed across GT resets; D3cold, S3 (still refused with VRAM allocated) and
eviction remain open.

Deviations: Linux revokes per buffer object on the `vram_userfault` list. NARF
revokes the card's whole BAR window, so mappings created while the function
is suspended are covered without a per-object list. NARF mmap is eager, so a
new VRAM mapping made while suspended starts unmapped and faults on first
touch. The synchronous i915 ioctl entry cannot resume the function, so a
VRAM PREAD/PWRITE through it is `EBUSY` while suspended.

Fixtures:

- `memory`: `smoke_device_revoke_removes_leaves_and_masks_installers` and
  `smoke_device_refault_waits_then_reinstalls_same_frame` (x86_64 and
  aarch64).
- `drivers/gpu/intel_gpu_gem`:
  `smoke_intel_vram_runtime_suspend_revokes_bar_mappings_and_gates_copies`.
- `drivers/gpu/intel_gpu_gt`:
  `smoke_gt_vram_cpu_revocation_reopens_pool_and_orphan_refault_fails`.

The park and resume wiring itself (`Owner::park`, the resume publication and
`VramRefault` with a live owner) needs the GT runtime and hardware. It is not
covered by these fixtures.

### Legacy i915 Perf UAPI & Query Compatibility — native fixtures added

Legacy Intel graphics tooling (such as Intel GPA, gputop, and Mesa perf query layers) relies on the classic i915 perf UAPI rather than the Xe observation interface. This slice completes compatibility for render nodes:

1. **`DRM_IOCTL_I915_PERF_OPEN` (0x76):**
   - Parses the 16-byte `drm_i915_perf_open_param` structure.
   - Reads the property array (`SAMPLE_OA`, `OA_METRICS_SET`, `OA_FORMAT`, `OA_EXPONENT`, `OA_PERIOD_EXPONENT`).
   - Translates i915 report format IDs (e.g. A32u40 -> 256 bytes) to the underlying OA engine format.
   - Opens a specialized stream file marked as `is_i915: true`.

2. **Stream File Operations & Ioctls:**
   - Prepending record headers: stream reads format samples according to the classic i915 record format, where each report is prefixed by an 8-byte `drm_i915_perf_record_header` (`type = 1` for `DRM_I915_PERF_RECORD_SAMPLE`, `pad = 0`, `size = 8 + report_size`).
   - Stream ioctls:
     - `I915_PERF_IOCTL_ENABLE` (0x6900): enables stream report collection.
     - `I915_PERF_IOCTL_DISABLE` (0x6901): halts stream report collection.
     - `I915_PERF_IOCTL_CONFIG` (0x6902): accepts `arg` directly as a u64 metric set ID, reconfigures the OA unit, and returns the previous active config ID.

3. **Dynamic Configurations:**
   - `DRM_IOCTL_I915_PERF_ADD_CONFIG` (0x77): parses 72-byte `drm_i915_perf_oa_config` containing UUID, register counts and pointers for mux, boolean, and flex registers. Registers are validated against whitelist rules and UUID uniqueness is enforced per card. Returns a unique positive config ID.
   - `DRM_IOCTL_I915_PERF_REMOVE_CONFIG` (0x78): takes a 64-bit config ID and removes it if not currently held active.

4. **Query Item 3 (`DRM_I915_QUERY_PERF_CONFIG`):**
   - Dispatched through `DRM_IOCTL_I915_QUERY`.
   - `DRM_I915_QUERY_PERF_CONFIG_LIST` (1): queries list of registered configuration IDs (`48 + 8 * n_configs`).
   - `DRM_I915_QUERY_PERF_CONFIG_DATA_FOR_UUID` (2): queries config metadata and registers matching a 36-byte UUID (`48 + 72` header + registers).
   - `DRM_I915_QUERY_PERF_CONFIG_DATA_FOR_ID` (3): queries config metadata and registers matching a 64-bit config ID.
   - Probing with capacity 0 returns required buffer length. Missing configs set item `length = -2` (`-ENOENT`). Flags at offset 40 must be zero (`-EINVAL` on violation).

5. **`I915_PARAM_PERF_REVISION` (GETPARAM 54):**
   - Returns 1 when an OA unit is published on the device backend, 0 otherwise.

Fixtures added:
- `drivers/gpu/intel_gpu_oa`: `smoke_i915_perf_open_add_remove_config_and_stream`, `smoke_oa_test_session_i915_header`.
- `drivers/gpu/intel_gpu_render`: `smoke_i915_perf_getparam_and_query_config`.

### Xe OAR/OAC Exec-Queue Streams & Steered Manual Capture — native fixtures added

This slice adds context-attached OA stream support on native Xe queues alongside steered manual error capture and diagnostic process facts:

1. **Xe OAR/OAC Exec-Queue Streams (`intel_gpu_oa`):**
   - Supports `DRM_XE_OA_PROPERTY_EXEC_QUEUE_ID` in `intel_gpu_oa::open`.
   - Validates queue existence (rejects missing queues with `NotFound`/`-ENOENT`) and single-lane width (rejects parallel queues `width > 1` with `EOPNOTSUPP`).
   - Validates engine-class format compatibility:
     - Render queue (class 0 / RCS0): allows OAR and OAG formats; rejects OAC formats with `InvalidData`.
     - Compute queue (class 4 / CCS0..3): allows OAC and OAG formats; rejects OAR formats with `InvalidData`.
     - System-wide streams (`exec_queue` absent): rejects context-only OAR/OAC formats with `InvalidData`.
   - Privilege policy:
     - Unprivileged callers can open event/batch-triggered streams on their own queue (`sample: false`), with stream ioctls (`ENABLE`, `DISABLE`, `CONFIG`, `STATUS`) and reads permitted without physical authority.
     - Periodic timer sampling (`sample: true`) and preemption holding (`no_preempt: true`, property 9) require privilege (`Gate::PHYSICAL`).
   - `Session`: records `exec_queue: Option<u32>`, `no_preempt: bool`, and `privileged: bool` with exposed accessors.
   - NO_PREEMPT (#1774): at enable the bound context's schedule is saved and its timeslice held at 0 (Linux `xe_oa_disable_preempt_timeslice`, which sets timeslice and preempt timeout to 0); the GuC Policy KLVs then carry EXECUTION_QUANTUM 0 and preempt timeout 0 for the next claim. Disable (and close/teardown) restores the saved pair — the user's own quantum, not the engine-class default Linux restores. A `configure_schedule` while the override is live records the new pair as the saved values, so the restore does not clobber a reconfiguration.
   - MI_REPORT_PERF_COUNT query sampling (#1774): open properties 14 (query buffer address) and 15 (query buffer size) name the opener's per-batch report buffer in the bound context's PPGTT; both or neither, query-mode streams only (bound queue, no periodic sampling, render/compute engine), whole reports, at least one, base report-aligned. At enable the exec path registers a sampler on the bound context; each submitted batch splices one Gen8+ 4-dword `MI_REPORT_PERF_COUNT` (`(0x28 << 23) | (4 - 2)`, address, per-stream report-ID sequence starting at 1) before the owned breadcrumb, so the report lands in the next rotating slot. The exec path refuses to submit while the buffer is not resident-writable in the VM. The destination is a PPGTT address, never GGTT: the i915 command parser requires `MI_REPORT_PERF_COUNT_GGTT == 0` and the GPU forces the per-process address space for this command.

2. **Steered Manual Capture (`intel_gpu_guc_capture`):**
   - `capture_manual_steered(family, engine, steered, read, read_steered)` reads steered render/compute extension registers (`lists.steered`) using MCR steering into `self.regs[CLASS]` with flags `STEERING_NEEDED | (group << 12) | (instance << 20)`.
   - `print_dump` formats steered registers grouped by DSS under `\tDSS_{dss}:` headings matching Linux `xe_guc_capture`.

3. **Coredump Process and Snapshot Time Facts (`intel_gpu_guc_capture`):**
   - `Queue` and `Capture`/`Report` carry optional `comm: Option<&'static str>`, `pid: Option<u32>`, and `snapshot_time: Option<(u64, u32)>`.
   - `print_dump` outputs `Process: {name} [{pid}]` (fallback `Process: unavailable`) and `Snapshot time: {secs}.{nanos:09}` (fallback `Snapshot time: unavailable`).

Fixtures added:
- `drivers/gpu/intel_gpu_oa`: `smoke_oa_exec_queue_oar_oac_streams`.
- `drivers/gpu/intel_gpu_error`: `smoke_guc_capture_manual_steered_and_dss_formatting`.
- `drivers/gpu/intel_gpu_error`: `smoke_coredump_process_and_snapshot_time_formatting`.


### USB-C display transports

The Meteor/Arrow external owner now admits pin assignment D, retaining the
connection's two-lane ceiling independently of the trained DP width. C20
VDR programming, TX overrides, resets, refclk/PLL requests and full stop
operate on display's PHY lane 0 and preserve USB's lane 1. Wide requests
against a narrow ownership shape refuse before programming. Native/legacy
VBT lane reversal reaches PORT_REVERSAL, maxPCLK lane selection and reversed
TX enables. DP-alt cable flip remains handled by the TCSS mux.

Live Thunderbolt-alt HPD now selects tunnelled AUX and the display's TBT
clock request/ACK sequence at RBR/HBR/HBR2/HBR3. It never takes TCSS PHY
ownership, writes C20 SRAM or resets the fabric's PHY. An empty port cannot
synthesize a tunnel. The existing USB4 CM or firmware still owns tunnel
provisioning; the GPU consumes the observed DP-IN route rather than guessing
an NHI domain/adapter from a USB-C connector index.

Display-14 MST uses dp_mst_mgr for MSTM enable, topology, remote EDID,
payload-table updates and ALLOCATE_PAYLOAD. Local admission accounts for
PBN on every topology hop, all 63 payload slots and the Type-C lane ceiling.
Streams use independent Pipe B-D reservations and distinct GGTT/physical
surfaces. Intel payload IDs follow pipe + 1; DATA_M1's TU count follows the
allocated slots. Only the primary transcoder owns DP_TP_CTL and the link
clock. Stream enable requires a fresh local ACT and sink ACT_HANDLED before
part 2 and transcoder enable. Topology notification rebuilds the set in
reverse stop order. Failed local stop quarantines the owner and backing.
The boot-console publication remains the first stream; multi-monitor
compositor/KMS expansion is not part of this transport change.

Pipe owners heap-allocate retained resource state before programming a
transaction, and display-layout proofs return heap-owned temporary snapshots.
Native fixtures bound inline DP/HDMI route values to 2 KiB and pipe-owner
values to 512 bytes, leaving room for nested watermark/DBUF planner scratch
on AArch64's 64 KiB bootstrap stack. Cloned snapshots keep independent
ownership; a failed transition retains the previous state.

The older Intel bridge now uses a source-qualified Dekel PLL for Tiger Lake
and Alder Lake-P/N rather than combo DPLL0. Linux binds ADL-N through the
ADL-P display descriptor as a display-13 subplatform with the same four
Type-C PHY ports. Bank selection and access are
serialized, masks preserve unrelated PLL fields, the DSSM reference selects
19.2/24/38.4 MHz coefficients, and rate-specific TX settings replace combo
BUF_TRANS. The bridge acquires TC-cold, AUX and PHY ownership before EDID.
It limits the link to the USB-PD grant, the sink's capabilities and the
physical assignment in `PORT_TX_DFLEXDPSP`. The register exposes single
lanes, adjacent low or high pairs, or all four lanes. Training writes the
chosen width into the port's `DFLEXDPMLE1` field before each attempt,
including fallback. SST checks the payload of the achieved link before
enabling the transcoder. The USB-PD detach hook releases the session after
verifying that the output stopped. Uncertain stop keeps the pipe, surface and
power reference; detach retries, and discovery resets only on success.
A successful native modeset publishes its physical surface to the framebuffer
consumer under the shared external-output serial namespace. Detach withdraws
only that exact serial before freeing the contiguous backing; a failed stop
keeps both, while a superseded session cannot withdraw the newer internal,
SST or Display-14 image. A transient NotReady or AUX/EDID wake failure is
retried by the active USB-PD task instead of being latched until the next
cable attach.
Alder Lake-S and unknown families remain refused on this path.
The older bridge requires native TC connector numbering. Its shared DDI type,
DDC map, retained session slots and DP bridge now expose Tiger Lake TC1..TC6
as `Ddi::D`..`Ddi::I`; ADL-P/N admit only TC1..TC4 through their typed
Dekel port count. It does not translate arbitrary UCSI numbering.
Source CR/EQ patterns and voltage/pre-emphasis precede matching sink AUX
writes. Fallback retunes the source with the buffer stopped; transcoder clock
selection follows each platform's port/PHY mapping and clears at teardown.

Sources: local Linux 7.3-rc4 intel_cx0_phy.c, intel_tc.c, intel_ddi.c,
intel_dpll_mgr.c, intel_dkl_phy.c, intel_dp_mst.c and their register headers;
the existing vendor-neutral MST/DP protocol implementations are shared.
No Intel silicon, Thunderbolt dock or Mesa acceptance is claimed by native
register/sideband fixtures. Test and build results are recorded in STATUS.md.

### HDCP 1.4 and 2.2 on external DP and HDMI (`narf.intel.hdcp=1`) — native fixtures added

`intel_hdcp` (engine), `intel_hdcp_msg` (HDCP 2.2 messages and the
firmware command set), `intel_hdcp_shim` (DP and HDMI sinks) and
`intel_hdcp_live` (properties, routes, service), after Linux 7.4-rc4
`intel_hdcp.c`, `intel_dp_hdcp.c`, `intel_hdmi.c`, `drm_hdcp_helper.c`,
`mei_hdcp.c`, `intel_hdcp_gsc_message.c` and `xe_hdcp_gsc.c`.

- Option: `narf.intel.hdcp=1` (strict). Without it no property is attached,
  the MEI HDCP client does not bind and no HDCP register is touched.
- Interface: the Intel card's non-eDP connector carries DRM "Content
  Protection" (Undesired/Desired/Enabled; userspace may not set Enabled)
  and "HDCP Content Type" (Type0/Type1), through GETCONNECTOR,
  OBJ_GETPROPERTIES, GETPROPERTY, SETPROPERTY and atomic commits. The
  driver reports DESIRED→ENABLED and ENABLED→DESIRED into the uAPI
  value; no uevent is sent (the DRM core has no connector property
  event).
- Routes: the connector binds to the function's single live SST route: a
  Gen12 HPD DP/HDMI session, a display 14+ DP/HDMI route, or the route a
  Tiger/Alder Lake-P firmware display lit (`TRANS_DDI_FUNC_CTL` readout;
  DP on combo DDIs whose sink is not eDP, HDMI with the DDI's default DDC
  pin). DP MST, several routes, older displays and other platforms'
  firmware routes are refused with typed errors (`HdcpError`).
- HDCP 1.4: fuse key load, An/Aksv (AUX `AKSV_SELECT`, GMBUS
  `GMBUS_AKSV_SELECT`), Bksv, R0'/Ri', repeater KSV FIFO with the hardware
  SHA-1 V' check, topology limits, link check every 2048 ms.
- HDCP 2.2: AKE/LC/SKE, DP stream-type errata, repeater topology and
  stream management, HDMI line-rekey control by display stepping, link
  check every 500 ms. Firmware: the MEI HDCP client
  (`narf_drivers_platform::mei_hdcp`, joined through
  `narf_drivers::hdcp_component`) on display 12/13; the media GT's GSC on
  14+ (with `narf.intel.media_gt=1 narf.intel.gsc=1`), whose worker
  submits each framed command from its packet object. Without the firmware
  type-0 content falls back to HDCP 1.4 and type 1 is refused.
- SRM: `display_hdcp_srm.bin` from the firmware registry; none revokes
  nothing, as in Linux.
- Not done: DP MST stream encryption, HDCP on cards driven by the Intel KMS
  owner's ioctl path (it refuses connector properties other than
  `CRTC_ID`), the `CP_IRQ` short pulse (RxStatus is polled every 10 ms),
  the HDCP debugfs files, Gen9/Gen11 port-indexed HDCP registers, and any
  silicon run.

## Completion of Intel iGPU and Discrete Arc Support

- **Long-Running (`LR_MODE`) & Fault-Mode (`FAULT_MODE`) VMs + `PREFETCH`**:
  `DRM_XE_VM_CREATE_FLAG_LR_MODE` (flag `2`, plus `SCRATCH_PAGE`) and
  `DRM_XE_VM_CREATE_FLAG_FAULT_MODE` (flag `4`, requiring `LR_MODE`) are
  admitted in `intel_gpu_xe` / `intel_gpu_xe_vm`. Long-running VMs forbid
  `SYNCOBJ` / `TIMELINE_SYNCOBJ` out-syncs, allow zero-operation
  `USER_FENCE` barriers, suppress the finite 5s/15s job watchdog while
  canceling active jobs on `EXEC_QUEUE_DESTROY`, and admit
  `DRM_XE_VM_BIND_OP_PREFETCH` (`op == 4`, `FAULT_MODE` only) to revalidate
  invalidated `MAP_USERPTR` ranges and migrate/evict mapped BOs between
  system memory (`region = 0`) and VRAM (`region = 1`).
- **Discrete VRAM Eviction, Small-BAR & Bidirectional Flat-CCS**:
  `DRM_XE_GEM_CPU_CACHING_WB` and small-BAR `NEEDS_VISIBLE_VRAM` admissions,
  bidirectional Flat-CCS save on VRAM eviction and restore on VRAM migration
  via `BCS0` / `intel_gpu_vram_clear`, dynamic OOM eviction during
  `GEM_CREATE` (pinning active scanout, CPU-mapped, VM-private, and busy
  objects), automatic exec re-migration of `preferred_vram()` BOs, and
  system-suspend drain (`allow_scanout = true`) are active across DG2 and
  Battlemage.
- **Integrated Display 20/30 (Lunar/Panther Lake) progress**:
  Display-20 PSR1 (`SRD_STATUS` SCL >= 1 precondition, entry setup frames,
  `Wa_18037818876`, `Wa_16025596647`), FBC on HDR planes (`Wa_18038517565`,
  skipping `Wa_22014263786`), DPT tiled panning via `DptLayout::with_origin`,
  S3 `panel_off` / `panel_on` relight and `system_suspend_admitted`, and
  PICA / Type-C TC1–TC4 DP output and HPD routing are wired into the shared
  KMS/external paths. Panther Lake reuses the DP 1.4 C20 tables through its
  PICA/Cx0 register view and runs each external pipe through the mandatory
  fixed-refresh VRR timing generator with guardband-aware watermarks. Combo
  DDI B (C10 on Lunar Lake, C20 on Panther Lake) takes DP, and HDMI TMDS runs
  on DDI B and declared legacy Type-C ports of both; Wildcat Lake's 30.02
  profile keeps TC1/TC2 DP only.
- **Discrete Arc Display Bring-Up (`DG2` Display 13 & `BMG` `Xe2_HPD` 14.01)**:
  `DiscreteDisplayIp::{Dg2, Xe2Hpd}` identifies discrete display engines on
  `Alchemist` and `Battlemage` (`GMD_ID_DISPLAY` 14.01), seeding DRM mode
  state (`intel_vram_scanout = true`) in `probe_discrete` and installing KMS
  via `install_discrete` when firmware Pipe A is lit. The GT owner starts
  beside a lit DG1/DG2/BMG display while every plane and cursor fetches below
  192 MiB and no DSB runs (`validate_discrete_display`), and a function probed
  lit keeps D0. Gen12 and Meteor/Arrow Lake desktops whose lit display matches
  no firmware handoff start the GuC owner under the same rule, with no KMS
  owner. `PteFormat::encode_ggtt_vram`
  and `Presenter::with_vram_scanout` program GGTT entries with `PTE_DM`, and
  `addfb2_intel` marks admitted VRAM scanouts non-evictable under normal OOM.
