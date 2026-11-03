# drivers/gpu/intel_gpu — Specification

> Status: **v0.49** (Stage 1 + Stage 2 codecs landed; lane 1
> #1010: canonical device table + census, panic-free probe with
> owned contiguous scanout, Gen12 display gate; Stage 5 RCS0
> command submission landed — see §8; PPGTT walker + GGTT
> bounds/flush discipline landed — see §9; forcewake domains
> landed — see §11; RC6 + DMC landed — see §12; suspend/resume
> + D-state transitions landed — see §13; external DisplayPort
> full single-stream landed — see §14; multi-pipe
> display + DP MST landed — see §16; fixed-mode MTL/Arrow WC GEM KMS
> flips connected — see §19 and `spec.md` §3; queued NONBLOCK, reset
> recovery, first-error diagnostics, userspace SLPC, BMG BCS8, Pipe-A CTM,
> protected passive GuC logs, dGPU telemetry, boot-selected multi-CCS,
> native gamma activation, client-free CCS reconfiguration, BMG package PL1,
> DSB color/primary transactions, GuC virtual queues, BMG PMT energy,
> PRIME sync-file imports, i915 virtual contexts, fixed-mode panning,
> additional power thresholds/intervals, GuC LFD export, width-two through
> width-four groups, full-AUX panel backlight, protected GuC failure bundles,
> fixed hardware cursor, DG2 visible VRAM, flush-coordinated GuC streams,
> parallel GPU user-fence joins, legacy gamma, BMG PSYS controls, EU-stall sampling,
> placement matrices, pre-CSC degamma, sampled read thresholds, execution coredumps,
> Gen12 GuC/fixed primary, Tile4, retained copies and runtime-power controls,
> Gen12 CTM/cursor/native LUTs, bounded loss-accounted GuC log fanout,
> joint primary/color and X/integer views, headless LNL/PTL main GT,
> Gen12 main-GuC media, retained CPU aliases, immutable Xe low-latency hints
> and exact LNL EU-stall observation; reviewed retained combo-B SST stop,
> per-object BMG i915 ASYNC and default-off exact-TGL HuC upload/auth/query
> pass debug and release native model gates; i915 context-frequency intent,
> private context publication and published-media SSEU defaults
> pass debug and release native model gates; BMG opt-in GPU-only VRAM,
> bounded i915 capture/protection and automatic-reset discovery
> pass debug and release native/integration gates; the unpublished
> MTL/Arrow standalone media GT lifecycle owner, display-14 DMC,
> DC_off and lit-panel DC5/DC6 services, and display14 resource
> transactions with live repartitioning and SAGV, and MTL external
> DP/HDMI outputs with Type-C ownership, owned hotplug, DC_off join,
> HDMI 2.0 scrambling and VBT port policy, display-14 FBC, PSR1 under
> KMS ownership and pipe DMC, and the default-off MTL media GuC with
> VCS/VECS scheduling, native Xe gt_id 1 and GT1 engine-cycles/topology
> queries, display-14 PSR on hardware inputs, and MTL external outputs
> on Pipes B–D beside the lit panel pass release native model gates —
> see §20).
>
> Display driver for Intel integrated graphics from Tiger Lake through Meteor Lake;
> render foundations also cover Arc Alchemist and Battlemage.
> References include Intel PRMs and the cited MIT-licensed Linux i915 ABI,
> command and register definitions.

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
  separate GGTT / PPGTT address, permission and PAT fields;
  Gen12 / Xe-LPG system-memory formats. Source: TGL PRM Vol. 5 "Memory Views".

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

### Stage 5+ (partially landed) — 3D / compute (TGL only)
- Command streamer (RCS0) ring submission — **landed** as the
  execlists path in `intel_gpu_rcs` (§8), with GGTT batches and
  attached-context PPGTT batches (§18).
- PPGTT per-context page tables and media submission — **landed**
  (§9, §18).
- Remaining: GT initialization, complete context/completion/reset ownership,
  Xe-LPG GuC submission and Mesa interoperability. The storage/context/query
  UAPI and immutable residency admission are described in §19.
  Out of scope for v1; the
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

Internal display programming admits Gen12 (Tiger Lake / Alder Lake /
Raptor Lake) and the separate Meteor/Arrow Lake Xe-LPG sequence.
Arrow Lake shares the `MeteorLake` classification and Linux's `mtl_desc`
display descriptor. Lunar Lake and Panther Lake refuse display programming;
their headless execution profiles do not qualify their display engines.
External sessions and PWM retain their separate generation gates below.

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

Scanout handoff requires an enabled firmware Pipe A and a successful
takeover mode. Panel power with no admitted mode allocates no internal
surface and publishes no synthetic 1024×768 display. The owned scanout
becomes active only after its primary-plane register program is armed.

Takeover and relight share generation dispatch (Gen12 versus Xe-LPG),
with Lunar Lake and Panther Lake refused before MMIO. Restore uses `modeset_fixed` on
the selected orchestrator, preserving the saved timing used to size the
new allocation even if EDID now advertises a different preferred mode.
Plane geometry, pitch and the complete 32-bit GGTT surface extent are
validated before pipeline teardown. This does not enable Xe-LPG PM or
establish physical display/suspend acceptance.
The external-session gate is separate: combo HPD enable/poll, DP, HDMI,
MST and USB-C DP Alt Mode remain Gen12-only until their Xe-LPG port
sequences exist. Unsupported generations return before HPD register
access; enabling the Xe-LPG internal panel must not enable Gen12 ports.
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

The RCS0 execlists engine model and kernel submission helper for Gen12.
Compiled only under the GPU crate's `intel` feature. This is not a complete
userspace render backend (see §19). The corrected Gen12 restore template has
13 initial register pairs, engine-relative LRI selectors and extended render
state groups, ending at dword 0xb9; XCS ends at 0x34. RING_CTL uses byte size
minus one page (128 KiB encodes 0x1f001) and the CSB has 12 entries. Fixed
source-cited vectors pin these values separately from the hardware model.
Public interface:

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
  controller on a default context.
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
  carve"). Selective fetch and Panel Replay are not
  offered on display 14.
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
(separate retained GuC owner); RC6p/RC6pp (absent on Gen12); runtime
event-handler reconfiguration (PSR/DCB routing belongs
to the display pipeline); DC3CO/DC9 targets; ADL-P
(display 13) pipe-DMC ranges; wiring park/unpark to GT
activity (the runtime-PM lane consumes this interface).

### 12.1 Display 14 DMC and DC states (`intel_gpu_dc_states`)

Meteor Lake and Arrow Lake (display 14.00) have a production DC-state
service; the Gen12 rules, tests and the inert §13 seam above are unchanged.
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

Production wiring, Meteor/Arrow Lake only. KMS install creates the service and
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
readout in this tree); no production caller fetches a
Gen12 blob yet, so the Gen12 reload path is fixture-proven
and inert until the probe-time fetch lands. Display 14 does
not use this core: its container is acquired, loaded and
restored across suspend by the DC service (§12.1), next to
the GT runtime owner that handles its system PM. RC6 enable-at-probe is
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
the DP-only steps: no M/N, no BUF_TRANS load, no link
training; the DDI buffer enables at the HDMI-fixed 4-lane
width.

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

Deliberate remainders: DVI signalling (same TMDS path,
no infoframes/SCDC — a follow-up, not filed here), YCbCr
4:2:0 and deep colour (character rate ≠ pixel clock —
the rate rule's premise is 8 bpc RGB), HDCP (separate
programme), HDMI 2.1 FRL, Type-C HDMI alt mode.

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
firmware setting. The current-CDCLK
readback decodes ratio + divider + squash popcount — under
squash the CDCLK_CTL decimal field is nominal and is not
trusted.

### 10.4 Gates and named remainders

- `display_supported()`: Gen12 + Meteor Lake. **Lunar Lake and Panther Lake
  stay off** — their display IPs require independently qualified
  clock-select fields, PLL tables and DDI arrangements; the MTL sequence
  must not claim them.
- `backlight_supported()`: Gen12 only. MTL's PWM path belongs
  to the backlight composition lane (PR #1037); the modeset
  shipping first must not claim a backlight it cannot drive.
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
- Pipe A's DMC is reported dark after this lane's crtc disable and lit
  before its port PLL (`intel_dmc_disable_pipe` / `intel_dmc_enable_pipe`
  call sites); a successful owned modeset records its panel mode
  (`owned_panel_mode`) for the Pipe B–D owner's adoption.
- Not programmed by this lane: watermark / DBUF allocation and
  PM demand outside a qualified display14.00 all-pipes-off modeset
  (that case runs the display14 resource transaction of §20; other
  cases retain firmware's allocation, and an inherited layout cannot be
  adopted by the external route), the owned panel's PM demand at its
  trained eDP rate (it keeps the HBR3 reservation the KMS fixed profile
  checks), computed (non-table) HDMI
  PLL states and HDMI 2.1 FRL (TMDS above 340 MHz with
  scrambling/SCDC is owned by `intel_gpu_xelpg_hdmi`, §20), DP 2.0
  UHBR rates (the DP stack tops out at HBR3), MST, a second external
  route at once, linetime/pipe-chicken/frame-start-delay programming
  of Pipes B–D, TBT-alt tunnels, pin-assignment-D lane ownership,
  CDCLK notifications on the inherited path (display 14
  has no PCODE CDCLK mailbox; only the owned transaction sends
  PM demand), and
  per-iteration TX-level updates inside the DPCD training loop
  (would need a source-side callback in the shared
  `dp_link_training`; levels are staged before training and
  re-applied after, the same simplification class as Gen12's
  preloaded DDI_BUF_TRANS table).
- §5's device table is unchanged by this lane: the MTL DIDs
  were already in the census; only their display gate moved.
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
  probed Gen12 part; no engine-query UAPI exists in the tree
  yet, and none is claimed here.
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
governs here). BCS0 (copy, base `0x22000`) is one more
`EngineSpec` away and deliberately out of this lane's
scope; MTL media belongs to the Xe-LPG GT generation and is
not claimed.


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
Fault/long-running VMs, USERPTR invalidation, remaining local-memory management,
media GT, multi-placement parallel submission/GPU joins and additional
query/property families remain completion work. Mesa and
physical execution remain separate acceptance gates.

The public contract is `spec.md` §3, "Intel render UAPI and address-space
admission". The modules are `intel_gpu_uapi` (wire definitions),
`intel_gpu_gem` (owned system memory), `intel_gpu_render` (per-open dispatcher,
contexts, VM handles and queries) and `intel_gpu_exec` (softpin admission and
immutable PPGTT residency). Same-card PRIME shares owned objects and stable,
globally distinct mmap offsets. Foreign attachments remain unavailable;
explicit sync-file imports join the same owned reservation. Both primary and
render nodes route these requests before shared DRM/KMS dispatch and acquire
mmap backing atomically.

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
Other engine/media/cache inventory, accelerated presentation and Intel
silicon/Mesa acceptance remain open.

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
remains unproven. Arc has GT-only binding without display admission or local
VRAM allocation.

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
graphics-engine reset before retiring RCS references. Autosuspend remains open;
the physical service retains its runtime-PM references.

`intel_gpu_gt_hw` adds capability-invoked MMIO, render-well wake and bounded
initial GuC/full-engine quiescence before PAT/MOCS programming. Staged physical
allocations reserve frames/VA without writing inherited GGTT entries. Installed
policies use MTL PAT3, DG2 PAT0 and BMG PAT2; MTL also installs UC PAT2 for
non-leaf PPGTT reads and Linux's non-coherent WT PAT1 (Mesa's scanout and
write-combining index). MTL display PAT0 is preserved.
MCR steering is serialized and restored, and BMG PTE writes drain the G-unit.

`intel_gpu_gt_runtime` starts a persistent per-function owner from Stage::Late,
validating D0, live PCI identity, PF registers and disabled SR-IOV VFs. MTL/Arrow
requires owned scanout takeover; DG2/BMG requires disabled inherited display
planes. Each owner retains the registered card, current PCI authority, dedicated
arena and immutable firmware asset. Async system-PM preparation proves stop
before saving configuration; the synchronous callback only verifies readiness.
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
unsafe `submit_kernel_batch`; user commands remain gated. `prepare_for_gt`
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
priming fence early. User isolation and synchronization remain prerequisites
for EXECBUFFER2 and Mesa acceptance.

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
scheduling admission, retaining owned storage until full reset. Media GT,
other engine classes, out-of-band workarounds and coordinated reset recovery
remain separate work.

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
The physical service remains RCS0-only, so modern CCS DUAL_QUEUE handling,
other engines, reset sequencing and RC6 acceptance remain separate work.
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
They do not admit userspace engines or commands. Media GT and L3 inventory
remain separate work.

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
and per-item -EFAULT for a bad copy. GuC submission-version remains -ENODEV until
the userspace scheduling interface is admitted. Native tests traverse both DRM
node types, GEM/mmap ownership, the GT discovery/publication chain and snapshot
queries after all GT DMA is freed.
Arc identity still adds no display binding or local VRAM. RCS0 availability
comes only from the live backend after execution-tested startup.

Gen12 owned resident submission, cache-flushed
post-sync breadcrumbs, terminal fences and loss retention have native hardware
models. Complete engine/media/cache inventory, accelerated PRIME/presentation
and real Mesa acceptance remain outstanding.

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
Adding USM must reserve/revoke ordinary userspace availability. Migration-style
kernel copies remain separate work.

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
client-free sysfs mode changes, width-one load balancing and bounded single-row
width-two through width-four groups; multi-placement groups and media GTs remain open.

### Remaining accelerated-driver completion work

The following foundation checkpoint and estimates predate the software
completion campaign. Section 20 tracks current completed profiles and open
exit conditions, including later priority, VM-dump, X-tiled and MERT work.
Native models and kernel diagnostics remain implementation evidence; physical
acceptance and complete acceleration require their separate gates.

The current continuation adds acknowledged GuC SLPC frequency bounds and
Base/PowerSaving profiles through the owned GT API (`intel_gpu_slpc`).
Stable main-GT RPn/RPe/RP0 discovery bounds requests before allocation;
range updates require matched replies and a final firmware readback. Pending
updates publish no confirmed status. Optional control failure retains the
shared buffer until verified stop and leaves command scheduling available.
BMG G21 keeps the source's 1200 MHz floor; graphics IP 20.01 conservatively
keeps the 2133 MHz MERT cap. Dynamic cap removal and the associated flush
protocol remain open. Wa_22019338487 does not apply to MTL graphics.

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
before power teardown. Gen12 production direct flips await its execution
backend; external planes and tiled/compressed layouts remain open. The detailed contract is in `spec.md`
§3, "Intel GEM framebuffers".

The runtime/SLPC/scanout foundation added 25 native fixtures: seven for
runtime accounting and engine progress, six for SLPC and twelve for scanout
ownership/latch evidence. KMS integration adds 35, including real mapped
copy, transaction/event publication, console epoch handoff, PSR, inherited
fetcher refusal, cancellation, suspend and reset quarantine. All 60 execute
and pass on both kernel architectures; x86_64 exercises public WC GEM flips
and aarch64 verifies WC refusal alongside the shared lifecycle paths. These
are native register/transport and ownership models, not Intel hardware
acceptance. The latest selected Intel/DRM/framebuffer regression groups pass
648 tests on x86_64 and 520 on aarch64, without failures or skips. Filters
are split to fit x86 PVH's 512-byte command-line bound. GPU/fb target CI
Clippy's three feature contexts pass on both architectures, as do all four
host vendor configurations, Intel debug builds, formatting, production boots
and both btrfs postflights per architecture.

| Area | Current checkpoint | Still required |
| --- | --- | --- |
| GuC execution | Owned GGTT/PPGTT jobs, primed/persistent user RCS0, BCS0, BMG BCS8 and selected CCS0–3 state, verified register policy, graphics-GT/engine workarounds on MTL/Arrow, DG2 and BMG | Media engines, remaining out-of-band workarounds and silicon qualification |
| Render UAPI | Native Xe queries/GEM/VM_BIND (incl. snapshot-pinned MAP_USERPTR), width-one GuC placement queues and single-row width-two through width-four COPY/COMPUTE groups, EXEC/user fences/per-engine cycles; explicit i915 compatibility on GuC cards with load-balanced context maps, WB softpin and explicit fences; context loss and fresh-epoch rebuild | USERPTR invalidation (MMU notifier), i915 GEM_USERPTR, fault/long-running VMs, multi-placement parallel submission and GPU user-fence joins, more queue/query families and Mesa interoperability |
| Engines and platforms | Main-GT DSS/EU discovery; RCS0, never-fused BCS0, BMG BCS8 and fuse-derived CCS0–3 scheduling with dense logical instances and client-free reset reconfiguration; separate Gen12 foundations | Media GT and media submission, independently sourced profiles for other IP |
| Memory and presentation | Owned system RAM, private tables, same-card CPU PRIME mappings and explicit fence imports; iGPU write-combining objects (retyped kernel aliases, WC mmap, SCANOUT, non-coherent PAT1/PAT2 binds); DG2/BMG visible VRAM (64 KiB DG2 pages and trusted data/CCS clear, guarded BMG CPU clear, WC BAR mmap, placement fallback); fixed-mode MTL/Arrow WC GEM KMS flips with console handoff, PM exclusion, queued NONBLOCK return, native error fences and hardware latch events; checked-copy fallback and bounded console/GEM GGTT windows; fresh-console retirement after GT reset | Small-BAR/unmapped VRAM, eviction/migration and general GPU copy jobs, VRAM PRIME/P2P, Gen12 production direct-flip admission, tiled/compressed modifiers and extra planes |
| Display | Gen12 paths and owned Xe-LPG internal-panel modeset; fixed-mode MTL/Arrow Pipe-A native CTM/gamma with DSB active replacement and joint primary/color arms; fixed 64x64 hardware cursor with owned PM_DEMAND/DBUF/MBUS/watermarks and separate retirement | Xe-LPG external-display admission, Arc display and platform-specific feature qualification |
| Power and faults | Owned GuC/RCS0/BCS0/BMG-BCS8 MSI wakeups with timer fallback, D0/wake ownership, verified full-reset teardown and fresh-epoch recovery; per-context hang recovery with LRC runtime accounting and engine-progress fallback; bounded first-error reports and protected automatic GuC log/CT failure bundles; idle D3hot runtime autosuspend for display-less discrete GTs with epoch-continuing resume; optional GuC SLPC/RC6 with acknowledged frequency bounds, Base/PowerSaving profiles and userspace policy replay; protected passive and flush-coordinated GuC log descriptors; cached DG2/BMG hwmon, fan/thermal readings, DG2 PL1 and BMG PL1/PL2/interval control | Full devcoredump and broader loss-accounted diagnostics, autosuspend with live VRAM (mapping revocation/eviction) or an active iGPU panel (display power wells/DC states), D3cold, dynamic BMG MERT cap removal/L2-flush frequency coordination and media-GT power management |
| Acceptance | Native register/CT/page-walk and ownership models on both kernel architectures | Intel silicon execution, suspend/resume and Mesa OpenGL/Vulkan interoperability |

#### Remaining-work status (2026-11-01)

**Size before KMS flip integration.** `tokei` code lines (comments and blanks excluded; inline
test modules included):

| | NARF Intel driver | Linux reference (b90c984d, C) |
| --- | --- | --- |
| GT / compute / UAPI | ~30.8k | xe core ~77.9k |
| Display | ~16.9k | i915/display ~144.3k (shared by xe) + xe/display glue ~1.6k |
| Total | ~47.7k (of which ~6.3k in `*_tests.rs` files) | ~223.8k |

**Pre-campaign estimate for full Linux-xe parity: ~100k–165k more Rust lines**, a
~150k–210k-line driver. For scale, NARF amdgpu is ~286k. The bounded
checkpoints below remove individual items; this estimate has not been
remeasured and is not a completion percentage.

| Area | Still to write (est.) | Main items |
| --- | --- | --- |
| VM and memory | 18–25k | Fault-mode, long-running and CPU-address-mirror VMs; USERPTR invalidation (memory-layer MMU notifier); VRAM eviction and migration through general copy-engine jobs; nonvisible VRAM; VRAM PRIME/P2P |
| Engines | 10–15k | MTL media GT (own GuC instance, VCS/VECS, HuC load/auth); parallel queues |
| Reliability and observability | 8–12k | Full devcoredump beyond bounded first-error reports; lossless GuC log streaming; OA and EU-stall perf streams |
| Power | 5–8k | D3cold; autosuspend with live VRAM or a lit panel; dynamic MERT caps; remaining hwmon controls |
| i915 compatibility | 3–5k | GEM_USERPTR, SSEU, perf, remaining params |
| Platforms | 8–12k | Lunar Lake (Xe2 iGPU), Panther Lake (Xe3), Tiger Lake/Alder Lake on GuC; roughly 2–4k per family |
| **GT subtotal** | **50–75k** | |
| Presentation | 6–10k | Gen12/external direct-flip admission; tiled and compressed modifiers; extra planes |
| Atomic modeset | 15–25k | Watermark and DBUF allocation; CDCLK changes with pcode; multi-pipe; bigjoiner; DSC; VRR |
| Outputs | 15–25k | Type-C/Thunderbolt PHY and DP alt mode; C20 HDMI 2.1; DP 2.0 UHBR; PSR2/panel replay; hotplug |
| Display power, color, HDCP, Arc display | 15–28k | DC states and DMC, FBC, display runtime PM; broader color profiles and transforms; HDCP; DG2/BMG display |
| **Display subtotal** | **50–90k** | |

**Usable Meteor Lake desktop subset: ~10–20k (pre-flip estimate).** Fixed-mode
zero-copy presentation is now implemented; this estimate still needs revision
after silicon bring-up and Mesa execution acceptance. A
read-only audit of upstream Mesa main's Xe backends (anv, iris and their
shared device code) found no startup blocker in the admitted UAPI. The five
device queries Mesa treats as fatal are served. The create-only low-latency
hint is now admitted on current qualified GuC hardware queues; software
VM_BIND refuses it. PXP, the state-cache perf fix, purgeable madvise and
fault-reporting VMs remain unadvertised. Scratch-page VMs, queue
priorities, bind queues, the VM_BIND op and flag set and WC
scanout/uncached buffers are admitted. What remains is execution behaviour,
which only hardware can show.

**Caveats.**
- Silicon bring-up is the unbounded term. Nothing here has run on Intel
  hardware or under Mesa.
- Estimates follow NARF's style: Linux-cited, inline native tests, about
  Linux's C density.
- SR-IOV, PXP and HDCP content protection are excluded from the subtotals
  except where listed.

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
pins keep aliasing the binder's memory. Linux parity still needs
`xe_userptr.c`'s invalidation/repin/rebind against unmap and replacement,
which requires a memory-layer MMU notifier. amdgpu GEM_USERPTR shares this gap.

iGPU `DRM_XE_GEM_CPU_CACHING_WC` objects are admitted (MIT Linux
b90c984d615e8ce2af96f5b1411a962d83fed2ad `xe_ttm_tt_create`,
`xe_gem_create_ioctl`, `xe_vm_bind_ioctl_validate_bo`). Their pages come
from `narf_memory::pageattr::WcPages`: every kernel alias is retyped
write-combining before publication (TTM `set_pages_array_wc`), user mmaps
are WC, kernel copies end with SFENCE and device publication needs no
CLFLUSH. Pages are restored write-back only after the last mapping, VM
binding and job drop the object. SCANOUT is admitted on the iGPU and is
EINVAL with WB caching. XE_COH_NONE binds (MTL PAT1 WT, PAT2 UC) are EINVAL
for WB objects and USERPTR. Deviation: PAT0, also XE_COH_NONE in Linux,
stays refused because its definition is left to firmware for the inherited
display. dGPU system memory stays WB as in Linux. aarch64 refuses WC
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

The `codex/intel-software-completion` branch starts from main's merge of
#1279 (`a2e0ec2ce`). Its backlog is every remaining software feature in §19,
including later platform profiles. Intel silicon, physical link qualification and
Mesa execution acceptance remain separately recorded evidence gates.
After merge #1308, `codex/intel-software-next` continues from merged main
`693d03ed9`; the following ledger includes both branches' checkpoints.

A feature closes only after its production entry point, resource lifetime,
reset/suspend behavior and refusal paths are implemented, its public contract
is documented, and relevant native tests pass. Architecture-neutral changes
use x86_64 regression tests by default; rerun aarch64 tests when its code or
behavior is affected. Cross-target builds and lint checks still verify shared
code portability. This iteration policy follows the maintainer's direction
to avoid redundant aarch64 test runs.
A query bit, codec, read-only audit or register model alone does not close a
production feature. Unsupported functionality remains unadvertised.

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
| VM/address mirrors | USERPTR invalidation/MMU notifier, i915 GEM_USERPTR, fault-mode/CPU mirrors and separately qualified nonfault long-running VMs | Open; memory/VM dependency |
| Local-memory management | Nonvisible allocation beyond the exact opted-in BMG headless profile; eviction/migration, alias revocation and preserved auxiliary system representations; VRAM PRIME/P2P | Open; bounded BMG allocation does not close migration/alias ownership |
| Client-free CCS reconfiguration | Card-lifetime primary/render leases; admin-gated asynchronous reset, all-engine startup proofs and fresh-epoch publication | Implemented; native fixtures pass |
| GuC width-one load balancing | Same-class placement mask, private per-restore hardware engine receipt, migration-aware watchdog, retained LRC/VM/retirement ownership | Implemented; native fixtures pass |
| i915 virtual contexts | LOAD_BALANCE proto-map extension through the production GuC backend, copied distinct same-class placements, transactional namespace and migration/retirement ownership | Implemented; native fixtures pass |
| GuC width-two through width-four groups | Single-row adjacent dense logical COPY/COMPUTE lanes, protected scratch/workqueue, contiguous IDs, independent saved/runtime state and all-lane retirement | Implemented; native fixtures pass |
| Engine scheduling | Additional platform-qualified queue protocols and protected queues with their firmware/security dependencies; pinned source gives current platforms no CGP class mask | Open; independent capability/firmware qualification |
| Media GT | Independent firmware/wake/cache/CT owner, VCS/VECS scheduling and HuC loading/authentication | Open; opt-in MTL/Arrow GT1 runs its own media GuC, schedules fused VCS/VECS with media-only ADS, default LRCs, CT GGTT invalidation and routed interrupts, and publishes native Xe gt_id 1 after per-engine private-PPGTT jobs retire, including GT1 engine-cycles and topology (with GT1's L3 bank entry) queries; with `narf.intel.huc=1` its media GuC DMA-loads and authenticates the MTL HuC and query7 type1 reports it; GSC HECI packets are modelled but unwired; GSCCS, GSC load, GSC HuC authentication and silicon acceptance remain |
| Diagnostics/performance | Full coredump/error-sysfs and batch capture beyond bounded native/i915 selected payloads, qualified log fanout, OA, additional sampling platforms and remaining i915 perf/SSEU/parameter interfaces | Open; explicit ownership and disclosure bounds |
| Atomic display | General watermark/DBUF/CDCLK/pcode transactions, multi-pipe and bigjoiner, DSC and VRR, tiling/compression beyond qualified X/Tile4 profiles and additional planes | Open; display14 resource transactions landed: all-pipes-off owned Pipe-A entry, live repartitioning, the Pipe B-D owner (production caller: the MTL external route; pipe-DMC bracket and IRQ-masked evasion around every arm) and SAGV with QGV derating; pipe scalers, bigjoiner, DSC and VRR remain |
| Output support | MTL external-display admission, Type-C/Thunderbolt PHY and alt mode, HDMI 2.1, DP UHBR, owned hotplug, qualified PSR2/panel replay | Open; MTL DP SST on DDI B/TC DP-alt and HDMI TMDS (DDI B, VBT-declared legacy Type-C; HDMI 2.0 scrambling/SCDC to 594 MHz) runtime-wired through one hotplug service on Pipes B-D beside the lit panel (live resource repartition, PM demand at the route port clock, pipe published with the image), Type-C ownership, owned PICA/south hotplug and display-14 AUX power implemented with native fixtures; VBT port facts (OpRegion VBT: ports, legacy Type-C, DDC pins, DP SSC; Gen12 DDC pins) and Gen12/MTL E-DDC implemented with native fixtures; DC-state join implemented; PSR1 on the KMS-owned MTL/Arrow Pipe-A eDP implemented (§20) with the display-14 watermark provider (Wa_14015648006) and the VBT PSR gate and wake times, so it can enable on hardware whose VBT enables PSR for the panel and whose Pipe-A watermarks are the owned modeset's; TBT, HDMI FRL, UHBR, a second concurrent external route, KMS flips/cursor on Pipe A while an external is lit, PSR while an external is lit, PSR2 selective fetch and Panel Replay open |
| DSB color transactions | Fixed progressive MTL/Arrow Pipe-A active LUT replacement and joint primary/CTM/gamma arms; retained command/primary mappings, dual hardware witnesses, cancellation/restoration markers and independent DMA retirement | Implemented; native fixtures pass |
| Linear primary panning | Fixed MTL/Arrow visible geometry/stride, bounded integer source viewport, aligned SURF/residual OFFSET in common DSB arm and full console/reset retirement | Implemented; native fixtures pass |
| Full-AUX panel backlight | Qualified MTL/Arrow VESA eDP caps/mode/width, arbitrated live-route AUX owner, retained brightness intent and verified panel suspend/relight | Implemented; native fixtures pass |
| Display services | Display runtime PM/DC states/DMC, FBC, broader color profiles/transforms, HDCP and Arc display | Open; MTL/Arrow DMC, DC_off references and lit-panel DC5/DC6 implemented (§12.1, native fixtures added); FBC on the fixed MTL/Arrow Pipe-A primary for KMS-owned GEM framebuffers only, with a CFB placed in DSM excluding WOPCM, the GSC region (only with a Wa_14019821291 media GT) and boot-framebuffer pages, proven outside system RAM, carved by a chunked off-present-path job (FBC stays off until it finishes); PSR1 wins over FBC while enabled (Wa_14016291713, no stepping readout); color, HDCP and Arc display remain |
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
| GT power/telemetry | D3cold, safe autosuspend with live mappings/panel, additional flush consumers/platforms and media power | Open; a lit iGPU panel keeps PCI autosuspend refused (Linux display wakeref) and idles through MTL/Arrow DC5/DC6 (§12.1); D3cold, mapping revocation, flush consumers and media power remain |
| Additional platforms | Broader display/platform services beyond the fixed Gen12 and headless LNL/PTL execution profiles | Open; primary-source register/firmware contracts |

The first four workstreams form the initial integration checkpoint. They do
not close the broader rows. Changes to memory/VM or other TCB members carry
the process-required safety argument and security review; the GPU lifecycle
checkpoint does not require those subsystems to change.

This checkpoint adds 27 native fixtures. All pass on x86_64; the 25 GPU
fixtures also passed on aarch64 before the redundant syscall ABI run was
stopped at the maintainer's request. Selected Intel/DRM/framebuffer groups
pass 673 tests on x86_64 and 545 on aarch64, with no failures or skips. The
x86_64 syscall ABI group passes 2252 tests with four existing harness skips
(`/proc` task identity and kernel/user-address discrimination). These are
native ownership/register/transport tests, not Intel silicon or Mesa evidence.
GPU/filesystem/userspace/fb target CI Clippy passes all three feature contexts
on both architectures. All four host GPU vendor configurations pass all-target
Clippy. Intel-only debug builds, production boots, both btrfs postflights per
architecture, formatting and diff checks pass.

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

This second checkpoint adds 36 native fixtures, all passing on x86_64.
Selected Intel/DRM/framebuffer groups pass 709 unique tests with no failures
or skips; a seven-test hwmon repeat is excluded from that unique total.
The queue-overlap fixture observes live job identities rather than assuming
priming consumed a fixed number of IDs; output rollback still verifies that
failed transactions consume none. First-error access-loss coverage checks all
28 register boundaries, including BCS8 and CCS0.

GPU/fb target CI Clippy passes all three feature contexts on both
architectures, and all four host GPU vendor configurations pass all-target
Clippy. Debug/release compilation passes on both architectures. The x86_64
production boot, both btrfs postflights, formatting and diff checks pass.
aarch64 QEMU was intentionally omitted because this checkpoint changes no
architecture-specific code or behavior. These native models do not establish
Intel silicon or Mesa acceptance. The broader VM, media, local-memory,
atomic-display, output and platform workstreams above remain open.

The third parallel checkpoint adds source-qualified boot-only multi-CCS,
1024-entry native gamma activation/bypass, extended dGPU controls/telemetry and
immutable i915 discovery/default-SSEU query handling. Production GuC cards
continue to select Xe; this compatibility dispatcher work does not admit a
new legacy execution backend or close that production acceptance gap. It
uses the same pinned Linux revision. All 40 new native fixtures pass on
x86_64; the selected Intel/DRM/framebuffer groups pass 749 unique tests with
no failures or skips. These include sparse CCS execution/retirement and exact
policy-loss admission, 46 first-error register access boundaries, color
cancellation/master replacement, and telemetry loss between sampling ticks.

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

Final GPU/fb target CI Clippy passes all three feature contexts on both
architectures. All four host GPU vendor configurations pass all-target
Clippy; debug/release compilation passes on both architectures. The x86_64
production boot, both btrfs postflights, formatting and diff checks pass.
aarch64 QEMU is intentionally omitted because no architecture-specific
production code or behavior changed. Intel silicon and Mesa acceptance
remain unrun; the broader workstreams above remain open.

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

All 25 new native fixtures pass on x86_64. Selected Intel/DRM/framebuffer
regression groups pass 774 unique tests with no failures or skips; repeated
runs of the main 185-test group are excluded from that unique total. These
conversations execute real client/sysfs entry points, full GuC reset/probe
sequences, the shared PCODE actor and actual DSB command buffers through their
programmed GGTT PTEs. They remain native models rather than Intel silicon or
Mesa acceptance evidence. GPU/fb target CI Clippy passes all three feature
contexts on both architectures, all four host GPU vendor configurations pass
all-target Clippy, and debug/release compilation passes on both architectures.
aarch64 QEMU is intentionally omitted because this wave introduces no
aarch64-specific production code; cross-target builds and lint still run.
The x86_64 production boot, both btrfs postflights, formatting, diff and final
source-integrity checks pass. The broader open workstreams above remain open.

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

All 27 new native fixtures pass on x86_64: seven virtual-queue, five mixed
display, nine BMG PMT and six PRIME-import conversations. Selected Intel/DRM/
framebuffer groups pass 801 unique tests with no failures or skips; the final
repeat of the 205-test main group is excluded from that total. Shared-core
regressions pass 2252 syscall ABI tests with four existing harness skips
(`/proc` task identity and kernel/user fixture-address discrimination), plus
62 AMD render tests without failures or skips. These remain native hardware
and ownership models; Intel silicon and Mesa acceptance are unrun.

GPU/fb/filesystem target CI Clippy passes all three feature contexts on both
architectures. All four host GPU vendor configurations pass all-target Clippy,
including a final default/Intel refresh after fixture-only corrections.
GPU/fb debug and release compilation passes on both targets. aarch64 QEMU is
intentionally omitted because this wave introduces no aarch64-specific
production code; cross-target builds and lint still run.
The x86_64 production boot and both btrfs postflights pass, as do formatting,
diff and final source-integrity checks. The broader open workstreams above
remain open.

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

All 31 new native fixtures pass on x86_64: six i915 interop/lifetime, six
viewport, fourteen hwmon and five LFD conversations. Selected Intel/DRM/
framebuffer groups pass 832 unique tests with no failures or skips, excluding
the repeated 230-test main group. Actual ioctl/sysfs paths, GuC selection and
private PPGTT execution, DSB command fetch through programmed GGTT PTEs, native
primary/color witnesses and retained failure/reset owners are exercised.
The mailbox regression distinguishes denied/all-ones final reply reads from
readable identity changes while preserving shared-port quarantine.

GPU/fb target CI Clippy passes all three feature contexts on both targets;
all four host GPU vendor configurations pass all-target Clippy, including
final default/Intel checks after fixture corrections. Debug/release builds
pass on both architectures. aarch64 QEMU is intentionally omitted because
this wave introduces no aarch64-specific production code. Intel silicon and
Mesa execution acceptance remain unrun; the broader software backlog remains
open.
The x86_64 production boot and both btrfs postflights pass. Formatting, diff
and final source-integrity checks pass as well.

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

This checkpoint adds 30 native fixtures. Selected Intel/DRM/framebuffer and
backlight groups pass 893 unique x86_64 tests, including all 31 shared
backlight regressions, with zero failures or skips. The queued-gang regression
fails with the original independent stall checks and passes with the corrected
unfinished-engine progress rule. GPU/fb production code passes target CI
Clippy in all three feature contexts on both architectures, all four host GPU
configurations pass all-target Clippy, and GPU/fb debug/release builds pass on
both targets. Fixture corrections also pass host all-target Clippy and the
native reruns. The x86_64 production boot, both btrfs postflights, formatting,
diff and final source-integrity checks pass. aarch64 QEMU is omitted because
this wave introduces no aarch64-specific production behavior.

The completion ledger now has 25 implemented checkpoint rows and ten broad
open workstreams. These rows differ substantially in scope and do not form a
completion percentage.

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

All 31 new native fixtures pass on x86_64. Selected Intel/DRM/framebuffer
and backlight groups pass 924 unique tests, including 31 shared backlight
regressions, with zero failures or skips. The x86_64 production boot and both
btrfs postflights pass. GPU/fb production target CI Clippy passes all three
feature contexts on both architectures; all four host GPU configurations pass
all-target Clippy. Both targets pass debug/release compilation. The aarch64
fixture control-flow correction passes final target and host lint; it changes
no x86 test or production behavior. Formatting, diff and final source-integrity
checks pass. aarch64 QEMU is intentionally omitted because no aarch64-specific
production behavior changes in this checkpoint.

The completion ledger has 28 implemented checkpoint rows and ten broad open
workstreams; rows differ substantially in scope and do not form a completion percentage. General VM
invalidation/faults, local-memory migration, media GTs, multi-placement/join
scheduling, broader diagnostics, atomic display/outputs/services, power and
additional platforms remain open. Dynamic BMG MERT cap lifting still needs
GSC readiness, frequency leases and host-L2 flush/unload coordination; the
2133 MHz cap remains. Intel silicon and Mesa acceptance remain separate gates.

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

All 25 new native fixtures pass. Selected Intel/DRM/framebuffer and backlight
groups pass 949 unique x86_64 tests, including all 31 shared backlight
regressions, with zero failures or skips. The real GT conversation verifies
sampler preallocation before startup acknowledgements/epoch publication,
authority-first refusal, bounded MCR reset escalation and storage retention
through independent full-GT reset proof. Package failure fixtures check exact
client transaction traces while allowing unrelated shared-mailbox work.
The x86_64 production boot and both btrfs postflights pass. GPU/fb target CI
Clippy passes all three feature contexts on both architectures, all four host
GPU configurations pass all-target Clippy, and debug/release builds pass on
both targets. Formatting, diff and final source-integrity checks pass.
aarch64 QEMU is omitted because no aarch64-specific production behavior changes.

The ledger now records 32 implemented checkpoint rows and ten broad open
workstreams. General VM invalidation/faults, local-memory migration, media GTs,
multi-placement/multi-row/render scheduling, broader diagnostics, atomic
display/outputs/services, power and additional platforms remain open. These
rows differ substantially in scope and do not form a completion percentage.
Intel silicon and Mesa acceptance remain separate, unrun gates.

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

All 22 new native fixtures pass. Selected Intel/DRM/framebuffer/backlight groups
pass 967 unique x86_64 tests, including all 31 shared backlight regressions,
with zero failures or skips. The full filesystem group passes 628 tests with
one existing RNG-registration skip; the syscall ABI group reports 2259 passing
executions and four existing `/proc` task-identity/address-discrimination skips.
The x86_64 production boot and both btrfs postflights pass.
GPU/fb/filesystem/userspace target CI Clippy passes all three feature contexts
on both architectures; all four host GPU configurations and host
filesystem/userspace pass all-target Clippy. Debug/release builds pass on both
targets. Formatting, diff and source-integrity checks pass. aarch64 QEMU is
omitted because no aarch64-specific production behavior changes.

The ledger records 36 implemented checkpoint rows and ten broad open workstreams.
Remaining work includes CGP multi-queue groups and dynamic priority, VM faults
and address mirrors, local-memory migration, media GTs, broader diagnostics,
general atomic display/outputs/services, power and additional platforms.
Intel silicon and Mesa acceptance remain separate, unrun gates.

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

All 25 new native fixtures pass. Selected Intel/DRM/framebuffer/backlight
groups pass 992 unique x86_64 tests, including all 31 shared backlight
regressions, with zero failures or skips. The new GT cancellation fixtures
verify partial/complete CPU clears, Busy admission before writes, flush
timeouts, independent post-reset L2 shutdown and uncertain last-owner retention.
The actual GT coredump fixture retains closed BOs through unanswered isolated
recovery and full reset; capture changes no execution lifetime. The x86_64
production boot and both btrfs postflights pass.

GPU/fb target CI Clippy passes all three feature contexts on both architectures;
all four host GPU configurations pass all-target Clippy. GPU/fb debug/release
builds pass on both targets, and formatting, diff and final source-integrity
checks pass. aarch64 QEMU is omitted under the maintainer's iteration policy
because no aarch64-specific production behavior changes.

The ledger now records 40 implemented checkpoint rows and ten broad open
workstreams. VM invalidation/faults/address mirrors, local-memory migration,
media GTs, independently qualified queue protocols, broader diagnostics,
general atomic display, outputs/services, GT power and additional platforms
remain open. These workstreams have different scopes and do not form a
completion percentage. Intel silicon and Mesa acceptance remain separate,
unrun gates.

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

All 49 new native fixtures pass. Selected Intel/DRM/framebuffer/backlight and
runtime-power groups pass 1048 unique x86_64 tests, including all 31 shared
backlight regressions, with zero failures or skips. The x86_64 production boot
and both btrfs postflights pass. GPU/fb/power target CI Clippy passes all three
feature contexts on both architectures; all four host GPU configurations pass
all-target Clippy. Debug/release builds pass on both targets, and formatting,
diff and final source-integrity checks pass. aarch64 QEMU is omitted under the
maintainer's iteration policy because no aarch64-specific production behavior
changes. The ledger records 45 implemented checkpoint rows and ten broad open
workstreams; Intel silicon and Mesa acceptance remain unrun.

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
  and current admin/syslog authority.
- The legacy Gen12 GGTT arena and PPGTT-root attachment enforce DMA39 before
  mapping/image writes; qualified DG2 arenas keep DMA46.

This checkpoint adds 39 native fixtures and rewrites four log-stream fixtures.
All 43 changed fixture names pass. Selected Intel/DRM/framebuffer/backlight and
runtime-power groups pass 1087 unique x86_64 tests, including all 31 shared
backlight regressions, with zero failures, skips or duplicate names. The x86_64
production boot and both btrfs postflights pass. GPU/fb target CI Clippy
passes all three feature contexts on both architectures; all four host GPU
configurations pass all-target Clippy. Debug/release builds pass on both
targets, and formatting, diff and final source-integrity checks pass. The last
portability corrections only scope fixture declarations and the Intel cursor
helper to their owning architecture/feature; the tested x86_64 behavior is
unchanged. aarch64 QEMU is omitted under the maintainer's iteration policy
because no aarch64-specific production behavior changes. The ledger records
49 implemented checkpoint rows and ten broad open workstreams. Intel silicon
and Mesa acceptance remain unrun.

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

All 58 new native fixtures pass in the debug kernel. The selected x86_64
run passes 1,144 Intel/DRM/framebuffer/backlight tests and 670 shared
filesystem/graphics/AMD tests, with no failures or duplicate names. All
1,087 previous Intel checkpoint fixtures and all 31 shared backlight
regressions remain covered. The shared group has one existing RNG-source
registration skip. Host GPU/filesystem all-target Clippy, workspace format,
diff and source-integrity checks pass. The full debug image needs a
6.2 MB KASLR relocation table; its x86_64 reservation is now 8 MiB, with
the existing image/slide/module-window assertions retained.

The ledger now has 56 implemented checkpoint rows and ten broad open
workstreams. Release native, production boot/btrfs and cross-target gates
remain pending for the combined follow-on branch. This local checkpoint
does not claim merge readiness or Intel silicon/Mesa acceptance.

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
OA, codecs, HuC on these LNL/PTL profiles, separate media GTs and physical
Intel/Mesa acceptance remain separate. Exact TGL has the distinct opt-in below.
All ten new fixtures pass in debug and release native kernels. The combined
branch passes 1,154 Intel/DRM/framebuffer/backlight tests and 670 shared
filesystem/graphics/AMD tests in each profile, with no failures or duplicate
names and one existing shared RNG-registration skip. All 68 new fixture names,
all 1,087 prior Intel fixture names and all 31 shared backlight regressions
are covered. The release production boot and both btrfs postflights pass,
closing the pending gates for the preceding integration batch as well.
GPU/fb/filesystem/graphics target CI Clippy passes all three feature contexts
on both architectures; all four host GPU vendor configurations pass all-target
Clippy. Changed-package debug/release builds pass on both targets, and
workspace formatting, diff and source-integrity checks pass. Two pure fixture
readers now compile on both targets; removing their obsolete x86-only guards
preserves the compiled x86 test code. aarch64 QEMU is
omitted under the maintainer's iteration policy because no aarch64-specific
production behavior changes. The ledger has 58 implemented checkpoint rows
and ten broad open workstreams. Intel silicon and Mesa acceptance remain
unrun. The subsequent three-feature checkpoint is recorded below.

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

All 37 new fixtures pass: 21 external-ownership, eight ASYNC and eight HuC.
Debug and release each pass 1,861 selected tests: 1,191 Intel/DRM/framebuffer/
backlight plus all 670 shared filesystem/graphics/AMD fixtures. All 1,087
prior Intel names, all 105 cumulative new names and 31 backlight regressions
remain covered, with no failures or duplicate names, no Intel skips and one
existing shared RNG-registration skip. Release production boot and both
btrfs postflights pass. Target CI Clippy passes all three feature contexts on
both architectures; all four host GPU vendor configurations pass all-target
Clippy. Changed-package debug/release builds pass on both targets; workspace
formatting, diff checks and all 103 frozen source/linker hashes pass.
aarch64 QEMU is omitted under the maintainer's iteration policy because no
aarch64-specific production behavior changes. Intel/S3/Mesa/codec acceptance
remains unrun.

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

All seventeen new fixtures pass: eleven frequency/publication and six
media SSEU cases. Debug and release each pass 1,878 selected native tests:
1,208 Intel/DRM/fb/backlight and all 670 shared filesystem/graphics/AMD cases.
All 1,087 prior Intel names, 122 cumulative new names and 31 backlight
regressions remain covered, with no failures or duplicate names, no Intel
skips and one existing shared RNG-registration skip. Release production boot
and both btrfs postflights pass. Target CI Clippy passes all three feature
contexts on both architectures; all four host GPU vendor configurations pass
all-target Clippy. Changed-package debug/release builds pass on both targets;
workspace formatting, diff checks and all 105 frozen source/linker hashes pass.
aarch64 QEMU is omitted because no aarch64-specific production behavior changes.
The reset fixtures use fresh GuCGt owners, not an actual RuntimeOwner/PCI/S3
coordinator. No physical Intel, Mesa, codec or frequency/performance result
is claimed. Local-memory takeover/allocation and OA remain separate work.

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

All thirty new fixtures pass: fifteen small-BAR, nine capture/protection and six
reset-availability cases. Debug and release each pass 1,908 selected tests:
1,238 Intel/DRM/fb/backlight plus all 670 shared filesystem/graphics/AMD fixtures.
All 1,878 prior selected names, 1,087 original Intel names, 152 cumulative new
names and 31 backlight regressions remain, with no failures or duplicate names,
no Intel skips and one existing shared RNG-registration skip. Release production
boot and both btrfs postflights pass. Target CI Clippy passes all three feature
contexts on both architectures; all four host GPU vendor configurations pass
all-target Clippy. Changed-package debug/release builds pass on both targets;
workspace formatting, diff checks and the exact frozen source/linker hashes
pass. aarch64 QEMU is omitted because no aarch64-specific production behavior
changes. These results are native models, not the physical acceptance below.

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

All seven debug and release groups each pass 1,912 unique tests with zero failures or duplicate names, no Intel skips and one existing shared RNG-registration skip. The four additions, exact TC replacement, preserved baseline/cumulative inventories and 31 backlight regressions pass. Release production boot and both btrfs postflights, both-target CI Clippy, four host vendor all-target Clippy configurations, both-target changed-package debug/release builds, formatting, diff and exact 119 source/linker hashes pass. aarch64 QEMU is omitted under the existing iteration policy; no aarch64-native execution result is claimed.

The fixtures use actual dispatch and an actual scheduler task over modeled
hardware. Full physical RuntimeOwner, positive firmware registry, PCI power
callbacks, S3 and controller/console publication remain manually traced rather
than executed by these new fixtures. Silicon, visible-pixel, complete-link,
Mesa, codec and performance acceptance remain unrun. No broad workstream closes.

### Fixed opaque XR30 input — software gates recorded

The bounded opaque XR30 slice adds LINEAR four-byte XRGB2101010 input to the existing exact fixed MTL/Arrow internal profile, with integer panning, real projected FIFO state and retained joint primary/color restoration. Current backend epoch publication and explicit reconciliation preserve owner authority. Output depth/HDR, other formats/platforms, global bandwidth policy and broader display work remain outside this slice. The ten broad workstreams remain Open.

The expected selection is 1,918 tests: 1,248 Intel/DRM/framebuffer/backlight plus 670 shared. All 1,912 NEXT10 names remain unchanged; six new registrations bring the cumulative new-or-replacement labels from 157 to 163. All 31 backlight regressions remain. The six additions belong to the existing intel_gpu_dsb namespace in group0 (369); group4 remains135 and group5 remains197.

All seven debug and release groups each pass 1,918 unique tests with zero failures/duplicates, no Intel skips and one existing shared RNG-registration skip. All six additions, all prior names,163 cumulative labels and31 backlight regressions pass. Release production boot/both btrfs postflights, both-target CI Clippy, four host vendor all-target Clippy contexts, both-target debug plus aarch64 release package builds, formatting, diff and all125 frozen source/linker hashes pass. The release native path supplies the x86_64 production release build. aarch64 QEMU is omitted under the existing iteration policy; no aarch64-native result is claimed. Version v0.37 has66 implemented rows and ten broad workstreams remain Open.

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

All seven release groups pass 1,930 unique tests with no failures and no Intel
skips. The only skip is the existing shared RNG-registration skip. The twelve
new tests run in group 6, which now selects `drivers/gpu/intel_gpu_media_gt`.
The release production boot and both btrfs postflights pass. The debug group
pass is deferred to the end of the current integration wave. These are native
register and CT models, not physical Intel evidence.

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
Without a registered media GuC, GT0's arena flush is unchanged. An unsolicited
G2H message on the idle media CT is a protocol failure that begins a stop. A
stop that cannot be proven leaves the owner retained, keeping its firmware memory
and the TLB registration.

The runtime starts one media GuC after the media GT lifecycle owner initializes.
Before a new GT0 arena is built (cold start), before runtime park and before
system-suspend preparation, it waits for a proven media GuC stop. Park refuses
as busy and suspend fails if that proof is missing. A retained media GuC leaves
GT0 failed instead of rebuilding the GGTT arena underneath firmware that may still
translate through it.

Remaining for this workstream:
- A media scheduler with media-only ADS engine classes. GT0's scheduler currently
  requires HWCONFIG, which Linux reads only on GT0.
- Media engine enablement, default contexts and the per-engine reset policy.
- VCS/VECS interrupt routing.
- CT-based GGTT invalidation once media submission is enabled.
- Native Xe exposure of gt_id 1, after which the GT1-unpublished conversation is
  replaced by positive and negative publication tests.
- GSC-loaded HuC (`huc_gsc`), which needs the GSC firmware/proxy path and stays
  unadvertised.

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

Integration of the media GuC and gate unit: all eight release groups pass
2,071 unique tests with no failures and no Intel skips; the only skip is the
existing shared RNG-registration skip. The existing TGL HuC fixtures pass under
the shared `boot_opt_in` grammar. With the option absent, the runtime builds no
media owner, `media::retire` returns `Done` without MMIO, GT0 install, park,
suspend and cold-start proceed as before, and the arena registers no second TLB.
The debug group pass is deferred to the end of the current integration wave.

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
shared arena stops writing GT1's GUC_TLB_INV_CR. The media scheduler's
per-context CT TLB_INVALIDATION covers GT1 instead, as send_tlb_inval_ggtt does
with CT and submission enabled. Stop reverts to MMIO. GT1 is declared ready
only after each engine runs its own private-PPGTT store job, retires it and
verifies the result.

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
exactly as before. The engine cycles and topology queries, width > 1 media
queues and GSC-loaded HuC remain open, along with silicon and Mesa acceptance.

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

Integration of the media engines unit: all eight release groups pass 2,077
unique tests with no failures and no Intel skips; the only skip is the existing
shared RNG-registration skip. Integration fixed
`smoke_media_gt_shared_ggtt_ct_mode_after_submission_enable`. It never
configured GT0's cache policy, so its arena allocations stayed unmapped and
never flushed; it now seeds the policy as the registered-TLB fixture does.
Once media submission is on, the arena stops writing the media
GUC_TLB_INV_CR. The media scheduler's TLB_INVALIDATION (0x7000) around context
registration and deregistration then covers GT1, as GT0's scheduler does for
GT0. Linux `xe_ggtt_invalidate` instead sends one CT invalidation per GGTT
update on each GT, so this is a deliberate NARF policy. Media 13.00 uses AUX
invalidation (MTL has no flat CCS) at the GSI-adjusted VD0/VE0_AUX_INV
(0x384218/0x384238), as `emit_aux_table_inv` adds the media `adj_offset`.
With `narf.intel.media_gt=1` absent, GT0 interrupt routing, scheduling, the
arena and the UAPI are unchanged. The debug group pass is deferred to the end
of the current integration wave.

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

Three source facts shape the remaining work.
- Linux sets the MTL HuC running after a DMA upload from its embedded CSS
  followed by media-GuC authentication (xe_uc_load_hw). That state is what
  query_uc_fw_version reports. GSC authentication is a second, PXP-oriented
  step.
- huc_auth_via_gsccs runs before xe_gsc_proxy_start and needs only a GSCCS
  packet to the PXP HECI client. The MEI/PXP/HDCP proxy is therefore out of
  scope for HuC.
- Linux's separate huc_firmware_path and gsc_firmware_path parameters make
  HuC and GSC independently optional.

The next wired slice is the MTL HuC on the media GuC: registry open, staging
with WOPCM, DMA from the CSS offset, the AUTHENTICATE_HUC action and the
GSI-adjusted HUC_KERNEL_LOAD_INFO. It should sit behind both the media-GT
option and the HuC option, and it needs no GSC. GSCCS bring-up, GSC load with
its stolen private object, Wa_14015076503 when NARF itself loads the GSC, and
GSC HuC authentication follow, behind a separate GSC option. Until then,
scheduling still refuses while GSC firmware is loaded, and HuC stays
unadvertised on MTL.

New fixtures register under `intel_gpu_media_gt`:
- `smoke_media_gt_topology_reads_gt1_fuse_mirrors_under_gt_wake` and
  `smoke_xe_mtl_media_gt1_engine_cycles_and_topology` cover the two queries.
- `smoke_media_gsc_firmware_identities_and_compatibility_policy`,
  `smoke_media_gsc_layout_parse_and_every_refusal`,
  `smoke_media_huc_gsc_image_versions_offsets_and_refusals`,
  `smoke_media_gsc_heci_packets_follow_xe_gsc_submit` and
  `smoke_media_huc_auth_modes_read_gt1_registers` cover the formats.

Integration: all eight release groups pass 2,100 unique tests with no failures
and no Intel skips; the only skip is the existing shared RNG-registration skip.
All seven new fixtures pass, but they are not physical Intel evidence. The
gt_id 1 engine-cycles checks run in the same order with the same errnos as
`query_engine_cycles`: clockid, then gt_id (beyond `max_gt_per_tile` or an
unpublished GT1 is EINVAL), then the engine lookup (EINVAL). A lost GT1 wake is
EIO, as Linux's forcewake failure is. It also unpublishes GT1 and begins the
media GuC's verified stop. At this checkpoint GT1's topology omits the L3 bank
entry, although `xe_gt_topology_report_l3` reports it for media versions below
30; the HuC unit adds it. GT0's topology also has no L3 bank entry, which
predates this work and still differs from Linux. `intel_gpu_gsc` is data
formats only and carries a temporary module-level dead-code allowance outside
kernel-test builds until a GSC/HuC owner consumes it. The production
(no-kernel-test) clippy contexts are clean. The debug group pass is deferred to
the end of the current integration wave.

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
GSC firmware load, Wa_14015076503 and GSC HuC authentication remain out of
scope, and scheduling still refuses while GSC firmware reports loaded.

GT1's topology now follows Linux for its L3 banks too. xe_gt_topology_init
runs load_l3_bank_mask on the media GT. xe_gt_topology_report_l3 keeps a media
GT's entry before media version 30, as part of the existing ABI. GT1's
MIRROR_FUSE3 and XEHP_FUSE4 are read with its other fuses and expanded by the
graphics 12.70 rule: each GT_L3_EXC_MASK bit selects a two-bank pair, repeated
every four bits for each MEML3_EN node. The 8-byte DRM_XE_TOPO_L3_BANK entry
sits between GT1's compute and EU entries. Mesa reads only gt_id 0, so this
changes no Mesa result. GT0's entries stay byte-identical; GT0 still reports no
L3 bank entry, a separate existing gap.

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
manually. No fixture was run in this checkpoint, and none is physical Intel,
Mesa or codec evidence.

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
- **PSR2 selective fetch and panel replay remain unqualified** (§10). PSR1
  is covered by the next subsection.
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

All seven release groups pass 1,948 unique tests with no failures and no Intel
skips. The only skip is the existing shared RNG-registration skip. Group 6 now
also selects `drivers/gpu/intel_gpu_dc_states`. The release production boot and
both btrfs postflights pass. The debug group pass is deferred to the end of the
current integration wave.

The FBC and external-DC follow-up passes all eight release groups (2,019 unique
tests) together with the external-route join. Group 6 now also selects
`drivers/gpu/intel_gpu_stolen` and `drivers/gpu/intel_gpu_fbc`. Integration
corrected `smoke_stolen_cfb_avoids_boot_fb_wopcm_and_gsc`: first fit places
its 2 MiB request in the free 4..6 MiB gap, so the system-RAM probe page now
sits inside that gap. The one-time GGTT aperture scan that excludes
boot-framebuffer pages runs in the first eligible `present()`, under the KMS
session mutex and a DC_off reference. It is not under an IRQ-safe lock, but
it is about 10^5 MMIO reads for a 256 MiB aperture in one executor poll.

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
computation is real, but a modeset that enables several pipes is not yet
wired. Nothing is advertised beyond the existing single-pipe profile.

Refused or not implemented: scalers, planar formats, async-flip
minimum watermarks, bigjoiner, DSC, VRR and Xe2+ clock/MDCLK changes.
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
block time without SAGV control. Pipe scalers remain open.

All seven release groups pass 1,973 unique tests with no failures and no Intel
skips; the only skip is the existing shared RNG-registration skip. That
includes the two restore-order fixtures that fail the post-plane PM demand
request after a clock decrease. Group 6 now also selects `drivers/gpu/intel_gpu_xelpg_resources`,
`drivers/gpu/intel_gpu_display_resources`, `drivers/gpu/intel_gpu_xelpg_live`,
`drivers/gpu/intel_gpu_xelpg_pipes` and `drivers/gpu/intel_gpu_xelpg_bw`. The
debug group pass is deferred to the end of the current integration wave.

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
  done interrupt. The Gen12 control word is unchanged and pinned. The fixtures
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

Remaining: the periodic runtime caller of `service_mtl_external` and
scanout publication still need to be added to the display runtime glue,
because this slice does not own `intel_gpu.rs`. Also open: concurrent
multi-pipe external use (DBUF/watermark repartition), UHBR (C20 MPLLA tables
and 128b/132b), HDMI TMDS/FRL on C10/C20, MST, DSC/FEC, audio, lane
reversal, TBT-alt tunnels, pin-assignment-D lane-0 ownership, a VBT
legacy-port source, the PW_2/PW_A fuse-distribution waits, per-iteration
source pattern/level updates during training, and PSR2/panel replay (worker
D). Native fixtures cover these paths. They are not physical Type-C, sink or
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
  representable by the shared Gen12 pin-pair encoder). HDMI is not yet
  selected by the hotplug service, which still activates DP only.
- Thunderbolt-alt stays refused. The display side (TBT clock request, TBT
  DDI clock select, AUX TBT_IO, IO_SELECT_TBT) does not by itself carry a
  stream: the DP tunnel through the USB4/Thunderbolt router is established
  by a connection manager this tree does not have.

New native tests: `drivers/gpu/intel_gpu`
(`smoke_mtl_external_hook_pass_allocates_publishes_and_withdraws`) and
`drivers/gpu/intel_gpu_xelpg_hdmi` (6).

Integration. The corrected `smoke_mtl_modeset_ddi_a_full_run` exposed that
the internal MTL modeset read the panel EDID over AUX before raising the AUX
power request. `XeLpgModeset::modeset` now raises it before the EDID read, as
`intel_dp_aux_xfer` holds the AUX power domain across every transfer. All
eight release groups pass 2,008 unique tests with no failures and no Intel
skips; the only skip is the existing shared RNG-registration skip. A new
eighth group selects `drivers/gpu/intel_gpu_xelpg_tc`,
`drivers/gpu/intel_gpu_xelpg_hpd`, `drivers/gpu/intel_gpu_xelpg_external` and
`drivers/gpu/intel_gpu_xelpg_hdmi`. The debug group pass is deferred to the
end of the current integration wave.

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

Remaining: a VBT parser (port facts, DDC pin overrides, dual-mode and
`max_tmds_clock` caps), E-DDC segments 1+ (the per-call GMBUS transport
cannot hold the segment pointer across a repeated START), HDMI FRL,
computed C10/C20 HDMI PLL states, audio, deep colour and YCbCr, and the
DC-state join. The Gen12 HDMI session still uses its older DDC engine and
SCDC sequence, so only its pin numbering changed. Native fixtures cover
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
max rate, DSC disable), PSR and PSR2 wake times and enable, and the LFP
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
panel and PSR owners and are not yet consumed.

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

Remaining: VBT consumers for the panel (PPS, eDP link, PSR, backlight) and for
the VBT `max_tmds_clock`, DP rate and lane caps; driving a VBT AUX remap, lane
reversal or a dedicated-external Type-C port; PnP-ID and OpRegion (SWSCI)
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
`clippy::result_large_err`. All eight release groups pass 2,052 unique tests
with no failures and no Intel skips; the only skip is the existing shared
RNG-registration skip. Group 7 now also selects `drivers/gpu/intel_gpu_vbt`.
The four GMBUS transport fixtures that failed after the pin renumbering alone
pass with the `do_gmbus_xfer` rewrite. The debug group pass is deferred to the
end of the current integration wave.

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
- **Remaining:** PSR2 selective fetch, early transport and cursor SU; Panel
  Replay stays refused. DIRTYFB clips are discarded today, so PSR2 would
  need the clip plumbing first.

Twelve native fixtures are registered under `drivers/gpu/intel_gpu_psr` and
were not executed in this slice. Six are register/sink models:
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

Integration of the PSR1 and pipe-DMC slices: all eight release groups pass
2,066 unique tests with no failures and no Intel skips; the only skip is the
existing shared RNG-registration skip. Group 7 now also selects
`drivers/gpu/intel_gpu_psr`, and all twelve PSR fixtures pass, including the
six on the production `Device`/`Guard` path. With no
`register_wm_level_disabled` provider, `compute_psr1` refuses with
`WmLevelUnknown` before `Psr::enable`. The one-time sink read is AUX DPCD
traffic, and no PSR register is written. The Gen12 probe-time PSR now skips
only display 14. Integration named the Wa_14015648006 provider type
(`WmLevelProvider`) and two fixture tuple types for Clippy. The debug group
pass is deferred to the end of the current integration wave.

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

Integration: all eight release groups pass 2,093 unique tests with no failures
and no Intel skips; the only skip is the existing shared RNG-registration skip.
Group 7 now also selects `drivers/gpu/intel_gpu_xelpg_wm`. Every new fixture
passes, including the production `Device`/`Guard` PSR conversations and the
LP5 = 0 `owned_resources` fixture. The carve job reads only GT-side registers:
the GGTT PTE array, GGC, STOLEN_RESERVED, the media GMD_ID and GSCPSMI_BASE,
and PCI config. It holds the KMS mutex per chunk with no DC_off reference,
yields between chunks and places outside the mutex. Lost access abandons the
slot, and the next present relaunches it. Known limitation: PSR refuses while
any external pipe is lit, because `Profile::capture` requires pipes B–D off;
the external-route pipe join must revisit this. The debug group pass is
deferred to the end of the current integration wave.
`smoke_xelpg_wm_latency_adjust_read_and_sagv_block` now uses one QGV point
and keeps zero points as the policy case.

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

Remaining: KMS flips and the cursor on Pipe A refuse while an external is
lit, because their fixed profile is the single-pipe layout. An active FBC or
DSB on the panel refuses the external route (`Pipe(Busy)`). The external is
refused next to an inherited, non-owned panel layout. PSR on the panel is not
coordinated with the live repartition. Releasing the last pipe with no panel
leaves CDCLK and PM demand raised until the next commit. Only one external
route runs at a time. Linetime watermarks, pipe chicken and frame-start delay
are not programmed for Pipes B–D. Production pipe-DMC calls are covered by
the DC service's own smokes and are inert without that service.

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
activation. All eight release groups pass 2,113 tests with no failures and no
Intel skips; the only skip is the existing shared RNG-registration skip.
Every new fixture passes. These are native models, not physical Intel
evidence. The debug group pass is deferred to the end of the current
integration wave.
