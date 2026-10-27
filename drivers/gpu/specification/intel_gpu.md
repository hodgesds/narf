# drivers/gpu/intel_gpu — Specification

> Status: **v0.10** (Stage 1 + Stage 2 codecs landed; lane 1
> #1010: canonical device table + census, panic-free probe with
> owned contiguous scanout, Gen12 display gate; Stage 5 RCS0
> command submission landed — see §8; PPGTT walker + GGTT
> bounds/flush discipline landed — see §9; forcewake domains
> landed — see §11; RC6 + DMC landed — see §12; suspend/resume
> + D-state transitions landed — see §13; external DisplayPort
> full single-stream landed — see §14).
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
  CMD/STATUS bit layout, pin-pair encoding (DDI A..F), E-EDID
  read transaction encoder, and the MMIO transport (`GmbusBus`):
  poll-counted HW_RDY / wait-phase waits, STOP-cycle +
  wait-idle teardown, SATOER NAK recovery, CYCLE_INDEX /
  GMBUS5 indexed transfers. Register map corrected against
  PRM Vol. 12 + i915 `intel_gmbus_regs.h` in #1018 (base
  0xC5100, GMBUS5 at +0x20, HW_WAIT_PHASE at GMBUS2[14]).
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
  (The GMBUS transport itself landed in #1018; the session
  wiring into the driver core is the remaining step.)
- Compute pipe / transcoder timing from EDID detailed-timing
  block; program PIPE / TRANS / PLANE through the Stage-2 codec.
- Take over scanout from UEFI GOP without re-training the link
  (modeset to firmware-supplied mode).

### Stage 4 (partially landed) — Frame buffer + KMS
- GTT entry table population from the Stage-2 codec.
- PPGTT page-table walks per the PRM memory model — **landed**
  (§9).
- Single-rectangle scanout from a CPU-mapped buffer.

### Stage 5+ (partially landed) — 3D / compute (TGL only)
- Command streamer (RCS0) ring submission — **landed** as the
  execlists path in `intel_gpu_rcs` (§8). GGTT addressing only.
- Remaining: PPGTT per-context page tables, media engines,
  full 3D pipeline state. Out of scope for v1; the
  kernel-resident driver only needs a display surface plus
  batch submission.

## 5. PCI device ID table

The canonical table lives in code as `intel_gpu::DEVICE_TABLE`;
PCI registration and classification both derive from it, and the
`smoke_device_table_census` fixture pins the code table to this
section. IDs are sourced from the public **`pci.ids`** database
(v2.2, Intel graphics rows). IDs that do not appear in pci.ids
(9A59 / 9AC9 / 9AC0 / 46B2 / 46A2) are **not** listed — an
earlier coverage pass named them in error.

| ASIC (`ChipInfo::asic`) | Device IDs |
| ----------------------- | ---------- |
| tigerlake (Gen12) | 9A40, 9A49, 9A60, 9A68, 9A70, 9A78 |
| alderlake-p (Gen12) | 4626, 4628, 462A, 4636, 4638, 463A, 46A0, 46A1, 46A3, 46A6, 46A8, 46AA, 46B6, 46B8, 46BA |
| raptorlake-p (Gen12) | 46B0, 46B1, 46B3, A720, A721, A7A0, A7A1, A7A8, A7A9, A7AA, A7AB, A7AC, A7AD |
| alderlake-m (Gen12) | 46C0, 46C1, 46C3 |
| alderlake-n (Gen12) | 46D0, 46D1, 46D2, 46D3, 46D4 |
| alderlake-s (Gen12) | 4680, 4682, 4688, 468A, 468B, 4690, 4692, 4693 |
| raptorlake-s (Gen12) | A780, A781, A782, A783, A788, A789, A78A, A78B |
| meteorlake (Xe-LPG) | 7D40, 7D45, 7D55, 7D60, 7DD5 |
| arrowlake (Xe-LPG) | 7D41, 7D51, 7D67, 7DD1, B640 |
| pantherlake (Xe3-LPG) | B080, B081, B082, B083, B084, B085, B086, B087, B08F, B090, B0A0, B0B0 |

Note: pci.ids labels 46B0/46B1/46B3 as AlderLake-P silicon; the
driver has always classified them `raptorlake-p` and the census
pins that existing behaviour (re-classification is out of scope
for lane 1).

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

Display programming is gated to Gen12 (Tiger Lake / Alder Lake /
Raptor Lake). Meteor Lake, Arrow Lake, and Panther Lake rows
identify and announce only; their display engines are tracked
in #1016. Because Arrow Lake shares the `MeteorLake`
classification, it inherits whatever display disposition that
generation carries — when #1016 opens Xe-LPG display for
Meteor Lake, Arrow Lake takes the same path deliberately:
Linux binds its display to the same `mtl_desc` descriptor.

## 6. Out of scope

- **Gen9 (Skylake / Kaby Lake / Coffee Lake) and Gen11 (Ice
  Lake / Jasper Lake / Elkhart Lake)** — explicitly out of scope.
  No device IDs are listed for them and none will be added to
  this driver: the codec layer is Gen12-shaped (combo-PHY DPLL,
  universal planes), so those generations would need a separate
  display model, not more table rows.
- Arrow Lake display — identification landed (#1023, §5);
  display support rides #1016's Xe-LPG family via the shared
  Meteor Lake classification, not a separate Arrow Lake path.
- Lunar Lake / Battlemage 3D — wait for PRM.
- Discrete Arc (Alchemist / Battlemage) — could plug into the
  same code path but requires the higher Xe-HPG / Xe2-HPG PRM
  set, which is partial today.
- Power/thermal-firmware blob (PUNIT) — opaque, loaded by the
  platform.
- HDCP / content-protection registers — out of scope for the
  KMS-grade driver.

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
  smallest ladder frequency satisfying the PRM rule
  `pixel rate <= 2 * CDCLK` (CD2X divider 1, pipe A).
- **Watermarks / DBUF allocation** — lane 1 programmed the
  PRM's "Display Buffer Allocation and Watermark Programming
  Prior to OS Boot" basics (160 DBUF blocks, one level). Lane
  Q6 (#1024) replaced that with the full latency-based
  algorithm — see the Q6 note below; the pre-boot programming
  remains as the fallback when the pcode latency read fails.
- **DDI_BUF_TRANS** — the modeset loads the swing table for
  the training start rate before link training and reloads if
  training settles elsewhere. RBR/HBR resolve to the HBR2 table
  (see `intel_gpu_ddi` for the rationale).
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

The RCS0 execlists engine for Gen12. Compiled only under the
gpu crate's `intel` feature. Public interface:

- `RcsEngine::new(mmio, alloc)` — allocate the engine status
  page, program `RING_HWS_PGA`, adopt the hardware CSB write
  pointer. Generic over `MmioWindow` + `GpuAllocator` so the
  protocol is fixture-drivable without a BAR; production uses
  `BarWindow` + `GgttArena`.
- `create_context() -> ContextId` / `destroy_context(id)` —
  a context owns a 48-page LRC image (register-state template
  on page 1), a 128 KiB ring, and a 1-page HWSP. Handles pack
  slot + generation; a stale handle is `UnknownContext`, never
  an alias. Destroy refuses (`ContextBusy`) while the context
  is loaded or has work queued/in flight.
- `write_batch(dwords) -> BatchBuf` — GGTT batch allocation;
  the batch must end with `MI_BATCH_BUFFER_END`.
- `submit(ctx, batch) -> request id` — appends
  `MI_BATCH_BUFFER_START` (GGTT) + an `MI_STORE_DWORD_IMM`
  breadcrumb (per-context seqno) to the ring, advances the
  image tail, and pumps the execlist ports. The context must
  be idle: this driver never patches an image the hardware
  may be restoring or saving, so re-submitting to a loaded
  context is `ContextBusy` (queued-but-unloaded contexts
  accept further submits and are covered together).
- `poll_completions() -> Vec<CompletedRequest>` — drains the
  Gen12 CSB from the engine status page (promote / preempt /
  complete), retires requests, frees batch allocations, and
  pumps the next ports. `wait_seqno` is the bounded-poll
  wrapper. Production glue: `submit_dwords` /
  `poll_default_completions` attach lazily to the probed
  controller on a default context.
- `attach_ppgtt(ctx, root_phys)` / `detach_ppgtt(ctx)` /
  `ppgtt_root(ctx)` — program a PPGTT root (§9) into the
  context image's PDP3 pair. Idle-context discipline, like
  every image patch here: a loaded or covered context refuses
  with `ContextBusy`; an unaligned or >39-bit root is
  `InvalidPpgttRoot`.

Invariants:

- ELSP writes are always full pairs in hardware order
  (port 1 high/low, port 0 high/low, posting read); a zero
  descriptor marks an empty port.
- Contexts address via GGTT by default: descriptor mode
  Legacy-64B, PDP image fields zero, batch ASI = GGTT. With
  a PPGTT root attached (§9) the PDP3 pair carries the root
  and the hardware walk runs under the context; batch
  allocations remain GGTT-backed and batch ASI stays GGTT
  until a VA-batch consumer lands.
- A context's requests retire strictly in submission order;
  a preempted context's covered requests return to the queue
  front and are resubmitted, never retired early.
- Every allocation (image / ring / HWSP / batch / status
  page) is arena-accounted; destroy and retirement return
  the arena to its prior balance.

Flagged for first-silicon verification (single named
constants in `intel_gpu_rcs`): `CSB_ENTRIES` = 8 (Gen11+
CSB depth), `RCS_IMAGE_PAGES` = 48 (allocation bound above
the hardware image size), and the descriptor Legacy-64B
mode choice.

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
- `map(mem, va, phys, pat, executable)` / `unmap(mem, va)` —
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

Flagged for first-silicon verification: in 4-level mode the
execlists context's PDP3 pair carries the PML4 root (as a
table entry, `phys | PRESENT`) and PDP0–PDP2 stay zero — the
encoding `attach_ppgtt` writes (§8). It is a single patch
site in `intel_gpu_rcs` if bring-up shows otherwise.


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
- ADL-P stepping workaround Wa_22012278275 (scrambled
  early-transport map) is not applied: this driver has no
  stepping readout yet.
- Sink sync latency is read from the last-actual field of
  DP_SYNCHRONIZATION_LATENCY_IN_SINK (bits [7:4]); i915's
  max-latency field (bits [3:0]) is the alternative —
  flagged for first-silicon verification, as is the
  PCH PPS base (0xC7200) on the south-display SKUs this
  queue covers.

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
bits — all under FORCEWAKE_ALL. NARF has no GuC, so the
host owns RC6: the control value is
`HW_ENABLE | RC6_ENABLE | EI_MODE(1)` = 0x8804_0000
(i915's host-owned form). The one omitted write from
i915's sequence is `GUC_MAX_IDLE_COUNT` — it programs
the GuC's idle policy, there is no GuC to consume it, and
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
module's.

Out of scope here: GuC-owned RC and `GUC_MAX_IDLE_COUNT`
(no GuC in NARF); RC6p/RC6pp (absent on Gen12); runtime
event-handler reconfiguration (PSR/DCB routing belongs
to the display pipeline); DC3CO/DC9 targets; ADL-P
(display 13) pipe-DMC ranges; wiring park/unpark to GT
activity (the runtime-PM lane consumes this interface).

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
is `region_generation().is_some()`, the same one the RCS
attach uses; Xe-LPG is excluded until #1016), probe
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
readout in this tree); no production caller fetches a
blob yet, so the reload path is fixture-proven and inert
until the probe-time fetch lands. RC6 enable-at-probe is
likewise a wiring step: the PM core owns the `Rc6`
lifecycle (snapshotted posture, park, re-enable), and
today nothing enables RC6 at probe, so in production the
snapshot's RC6 bit is currently always off. D3cold is not
used (the bus layer supports D3hot only; the link stays
up and config survives). PSR/DC-state runtime policy and
S0ix are out of scope.

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
- `HpdMonitor` / `poll_hpd_event` — GEN8 DE Port block
  (ISR 0x44440, IMR 0x44444, IIR 0x44448, IER 0x4444C; combo
  hotplug bits at `1 << (3 + ddi_index)`). Level rise/fall is
  Connect/Disconnect; a latched IIR bit on a steady high level
  is the DP short pulse → `RetrainRequired`. Production glue
  in `intel_gpu::poll_dp_hpd_events` drains events, allocates
  the scanout (probe's allocator/lifetime), and publishes
  through the §7 ACTIVE + observer protocol.

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
and if the fallback ladder settles elsewhere the DPLL, M/N,
port width and BUF_TRANS are reprogrammed to the trained
configuration before the DDI buffer enables. The legacy eDP
path (`Modeset::modeset`) is byte-for-byte unchanged.

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

Deliberate remainders: DP MST and multi-pipe (#1017),
Xe-LPG display (#1016), Type-C HPD via the GEN11 DE HPD block
(the Alt-Mode bridge's DDIs), DSC/FEC, and the HPD IRQ
handler itself (interrupt enables are programmed; the
session is poll-driven until an IRQ consumer lands).
