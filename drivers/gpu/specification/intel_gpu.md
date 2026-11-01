# drivers/gpu/intel_gpu — Specification

> Status: **v0.22** (Stage 1 + Stage 2 codecs landed; lane 1
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
> native gamma activation, client-free CCS reconfiguration, BMG package PL1
> and DSB color transactions — see §20).
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

Scanout handoff requires an enabled firmware Pipe A and a successful
takeover mode. Panel power with no admitted mode allocates no internal
surface and publishes no synthetic 1024×768 display. The owned scanout
becomes active only after its primary-plane register program is armed.

Takeover and relight share generation dispatch (Gen12 versus Xe-LPG),
with Panther Lake refused before MMIO. Restore uses `modeset_fixed` on
the selected orchestrator, preserving the saved timing used to size the
new allocation even if EDID now advertises a different preferred mode.
Plane geometry, pitch and the complete 32-bit GGTT surface extent are
validated before pipeline teardown. This does not enable Xe-LPG PM or
establish physical display/suspend acceptance.
The external-session gate is separate: combo HPD enable/poll, DP, HDMI,
MST and USB-C DP Alt Mode remain Gen12-only until their Xe-LPG port
sequences exist. Unsupported generations return before HPD register
access; enabling the Xe-LPG internal panel must not enable Gen12 ports.

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

A `BacklightDevice` over DPCD through the Intel AUX machinery,
registered into the arbitrated backlight stack (see §10's PPS
composition: the device is a candidate alongside the PWM device,
not a replacement for it):

- Registers: `BACKLIGHT_BRIGHTNESS_MSB` 0x722,
  `BACKLIGHT_BRIGHTNESS_LSB` 0x723 (issue #957's VESA eDP
  backlight block). AUX framing is the spec-shaped `dp_aux`
  layer (DP 1.4a §2.7); the device is generic over
  `AuxChannel`, so the production `IntelAux` transport and
  the fixture's panel model run the same device code.
- Field width is a per-panel fact (`lsb_used`): 16-bit
  MSB-first levels, max 0xFFFF, when the LSB register is
  used; the MSB byte alone, max 0xFF, otherwise. Reads and
  writes carry exactly the field width — never a blanket
  2-byte access on an 8-bit panel. Semantics follow Linux
  `intel_dp_aux_backlight` / `drm_edp_backlight` as the
  public reference implementation of the VESA protocol.
- Kind is Raw (direct hardware control). Ties keep the
  earliest registration, so install ordering against
  `intel_bl::install` decides ownership on dual-path panels.
- `install(channel, lsb_used)` is the registration seam;
  no probe call site installs the device yet. Named
  remainders (grounding gap, not oversights): mode
  selection at 0x721, the 0x700 capability probe, and the
  0x720 display-control enable bit — their bit encodings
  could not be pinned to a citable source in this lane
  (VESA eDP text paywalled; public Linux sources use
  symbolic names), so they are not programmed here. The
  follow-up probes the caps, installs only on full-AUX
  panels, and installs before `intel_bl::install` so the
  DPCD device wins the Raw tie on AUX-only panels. The
  generic PWM panel backlight half of #957 is likewise
  remainder. Fixture: a panel-side DPCD model asserting
  the wire frame byte-for-byte, the field-width
  transcripts, and the NACK → 0 read contract.

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

- `probe_sink(mmio, ddi) -> HdmiSinkProbe` — the complete
  EDID over DDC, the preferred mode, the HDMI Forum VSDB
  capabilities, and whether the mode's character rate
  demands scrambling. No display registers are touched.
- `activate(mmio, probe, fb) -> HdmiConnection` — SCDC
  configuration where required, the WRPLL modeset
  (`Modeset::modeset_hdmi`), the AVI infoframe, then
  display-audio publication. `connect` composes the two.
- `disconnect(mmio, conn)` — audio disable + sink clear,
  DIP disable, pipeline teardown.

DDC runs over the **GMBUS codec** (`intel_gpu_gmbus`): the
base EDID block uses the codec's own read program verbatim;
indexed and segment-pointer reads, and the SCDC writes,
compose the codec's field helpers — no second DDC
transport. The session drives the codec's documented
caller sequence (program GMBUS0/GMBUS1, poll GMBUS2 via
`GmbusStatus`, drain/fill GMBUS3, restore GMBUS0 = 0)
directly, because Q3 (#1018) has not landed a transport
yet; when it does, the engine functions in
`intel_gpu_hdmi` are the swap-out point. The GMBUS_BASE
correction (0xC510 → 0xC5100) and the duplicated GMBUS2
HW_DONE bit are #1018's and are not duplicated here — the
session and its fixtures key off the codec's constants,
never a private copy of the base.

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
HF-VSDB declares SCDC_Present; read-modify-write
TMDS_CONFIG (0x20) setting SCRAMBLING_ENABLE | ratio 1/40;
wait out the specification's 1 ms minimum settle
(poll-counted, per the #879 poll-budget discipline); read
SCRAMBLER_STATUS (0x21) and require the scrambling bit,
else `ScramblingVerifyFailed`. Configuration runs before
the modeset binds the transcoder.

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

HPD is the §14 GEN8 DE Port block, shared: HDMI sinks
answer DDC, DP sinks answer AUX, so the glue
(`intel_gpu::handle_dp_hpd_event`) tries the DP connect
first and falls back to HDMI; a fall tears down whichever
session owns the DDI. Short pulses remain DP-only.

Invariants:

- A ≤340 Mcsc connect produces zero SCDC-slave traffic
  (fixture-asserted over the recorded GMBUS programs).
- SCDC writes precede the first TRANS_DDI_FUNC_CTL write
  (fixture-asserted over the recorded write log).
- The modeset's CFGCR0/CFGCR1 writes for a mode equal the
  WRPLL fixture rows for that TMDS clock.
- Disconnect clears the ELD publication before the
  pipeline comes down, and clears the DDI buffer last.

Fixtures: a GMBUS sink model (EDID store + SCDC register
file decoding the GMBUS1 program fields itself) exercising
1080p connect with no SCDC traffic, 4K60 connect with the
SCDC RMW + verify + func-ctl bit pins, 4K60 refused
without SCDC, scrambling-verify failure, sink NACK,
4-block EDID over the E-DDC segment pointer, HF-VSDB
parsing past a decoy HDMI Licensing VSDB, infoframe
byte pins, and disconnect teardown order.

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
| DDI A | 0x64000 | C10 | 0 | 0 | AUX_A (0) |
| DDI B | 0x64100 | C10 | 1 | 1 | AUX_B (1) |
| TC1 | 0x16F200 | C20 | 2 | 9 | AUX_USBC1 (3) |
| TC2 | 0x16F400 | C20 | 3 | 10 | AUX_USBC2 (4) |

Port register offsets are per-port absolutes, not a uniform
stride (e.g. the message-bus timer sits at +0xD8 on DDI A/B but
+0x58 on the TC ports). `DDI_CLK_VALFREQ` exists only on the
C10 ports; C20 carries its rate in the PHY's serdes-rate VDR.

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
tables) → lane reset + powerdown staging (P2 reset, then P0
active) → PLL state → per-TX single-TX disables →
`DDI_CLK_VALFREQ` (C10 only) → PCLK PLL request/ACK. Every MTL
port also traverses the die-to-die (D2D) link, enabled
unconditionally in the retrain preamble.

### 10.3 Power wells and CDCLK

Xe-LPD well topology (`PWR_WELL_CTL2` = 0x45404,
`PWR_WELL_CTL_AUX2` = 0x45444, HSW request/state encoding):
PW_1 (idx 0, transcoder A + DDI A/B) → PW_A (idx 5, pipe A) →
the port's AUX well. CDCLK runs on the fixed 38.4 MHz MTL
reference: six rungs (172.8–652.8 MHz), the two lowest reached
by squash waveforms programmed in `CDCLK_SQUASH_CTL`; the
modeset raises CDCLK to the `pixel_clock ≤ 2 × CDCLK` floor
and never lowers a faster firmware setting. The current-CDCLK
readback decodes ratio + divider + squash popcount — under
squash the CDCLK_CTL decimal field is nominal and is not
trusted.

### 10.4 Gates and named remainders

- `display_supported()`: Gen12 + Meteor Lake. **Panther Lake
  stays off** — Xe3-LPD is a different display IP generation
  (widened clock-select fields, different PLL tables and DDI
  arrangement); the MTL sequence must not claim it.
- `backlight_supported()`: Gen12 only. MTL's PWM path belongs
  to the backlight composition lane (PR #1037); the modeset
  shipping first must not claim a backlight it cannot drive.
- Region enumeration: `RegionGeneration::XeLpg` — display at
  0x40000/0x40000 plus the TC block at 0x16F000/0x1000, and
  **no DPLL region** (Xe-LPG has no DPLL block; Gen12's DPLL
  range is the TC block here).
- Not programmed by this lane: watermark / DBUF allocation
  (i915 computes MTL allocations from pcode latency tables;
  firmware's allocation is retained), HDMI PLL states, DP 2.0
  UHBR rates (the DP stack tops out at HBR3), MST / multi-pipe,
  DVFS/pcode notifications around CDCLK changes, and
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

Production GuC owners now select native Xe on both render and primary opens.
The new path implements Xe engine/memory/config/GT/HWCONFIG/topology queries,
correlated RCS engine/CPU timestamps through the live reset/forcewake owner,
system GEM creation/mmap, persistent VM binding metadata, RCS0 and software
bind queues, binary/timeline syncs, GPU and CPU user fences and masked waits.
Its immutable per-execution PPGTT roots retain partial BO ranges and aliases;
scratch/NULL mappings use shared hardware NULL tables with private path copies.
Xe GPU ordering is explicit while terminal dma_resv fences exclude CPU copies.
VM-attached BO identities cannot be exported or rebound to a different VM.
Native queue priorities and timeslices reach the real GuC policy KLVs.
Legacy backends retain the i915 compatibility profile described below.
Fault/long-running VMs, compute/media engines, VRAM, scanout allocation
and additional query/property families remain completion work. Mesa and
physical execution remain separate acceptance gates.

The public contract is `spec.md` §3, "Intel render UAPI and address-space
admission". The modules are `intel_gpu_uapi` (wire definitions),
`intel_gpu_gem` (owned system memory), `intel_gpu_render` (per-open dispatcher,
contexts, VM handles and queries) and `intel_gpu_exec` (softpin admission and
immutable PPGTT residency). Same-card PRIME shares owned objects and stable,
globally distinct mmap offsets; foreign attachments/sync-file imports are
unavailable. Both primary and render nodes route these requests
before shared DRM/KMS dispatch and acquire mmap backing atomically.

Native terminal fences now back the shared per-object dma-buf reservation.
GuC and Gen12 resident admission check the whole residency list before adding
READ/WRITE fences; readers can overlap, conflicting writers return busy, and
kernel CPU copies use the same admission gate. Cache publication follows
reservation. Failure after reservation releases the graph before signalling;
uncertain DMA lifetime keeps reservations through timeout/cancel until proven
full reset. Independent GuC LRCs do not share an ordered dma-fence context.
GEM_BUSY exposes render-class reader/writer bits. Async GEM_WAIT preserves one
relative timeout deadline across parking and writes remaining nanoseconds;
PREAD/PWRITE and CPU-domain waits respect reservations. PRIME SYNC START waits
for conflicting access, END orders coherent RAM, and shared names and
EXPORT_SYNC_FILE use the generic dma-buf fd/copyout protocol. Existing mappings
still require caller exclusion; this does not enable external fence import,
external fence import or Mesa acceptance. Linux references are
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
potentially live allocation; release requires verified GuC reset plus firmware
DMA idle, or an explicit unsafe proof from the GT owner. One-shot DMA publication
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
The detailed contract is in `spec.md` §3. Dynamic client-free sysfs mode changes,
load-balanced/parallel queues and media GTs remain open.

### Remaining accelerated-driver completion work

Continue these dependencies on the current Intel branch. Existing native
models and kernel diagnostics are implementation checkpoints, not physical
acceptance or a claim of complete acceleration.

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
| Render UAPI | Native Xe queries/GEM/VM_BIND (incl. snapshot-pinned MAP_USERPTR)/RCS and COPY queues/EXEC/user fences/per-engine cycles; i915 compatibility with legacy BLT ring, context engine maps and explicit fences; context loss and fresh-epoch rebuild | USERPTR invalidation (MMU notifier), i915 GEM_USERPTR, fault/long-running VMs, i915 load balancing/parallel submission, more queue/query families and Mesa interoperability |
| Engines and platforms | Main-GT DSS/EU discovery; RCS0, never-fused BCS0, BMG BCS8 and fuse-derived CCS0–3 scheduling with dense logical instances and client-free reset reconfiguration; separate Gen12 foundations | Media GT and media submission, independently sourced profiles for other IP |
| Memory and presentation | Owned system RAM, private tables, same-card CPU PRIME mappings; iGPU write-combining objects (retyped kernel aliases, WC mmap, SCANOUT, non-coherent PAT1/PAT2 binds); Battlemage visible VRAM (zeroed pool, DM PTEs, WC BAR mmap, placement fallback); fixed-mode MTL/Arrow WC GEM KMS flips with console handoff, PM exclusion, queued NONBLOCK return, native error fences and hardware latch events; checked-copy fallback and bounded console/GEM GGTT windows; fresh-console retirement after GT reset | DG2 VRAM (64K pages + CCS clear), small-BAR/unmapped VRAM, eviction, GPU clears, VRAM PRIME/P2P, Gen12 production direct-flip admission, tiled/compressed modifiers and extra planes |
| Display | Gen12 paths and owned Xe-LPG internal-panel modeset; fixed-mode MTL/Arrow Pipe-A native CTM/gamma with DSB active replacement and joint color arms, retained state and hardware completion | Xe-LPG external-display admission, Arc display and platform-specific feature qualification |
| Power and faults | Owned GuC/RCS0/BCS0/BMG-BCS8 MSI wakeups with timer fallback, D0/wake ownership, verified full-reset teardown and fresh-epoch recovery; per-context hang recovery with LRC runtime accounting and engine-progress fallback; bounded first-error reports; idle D3hot runtime autosuspend for display-less discrete GTs with epoch-continuing resume; optional GuC SLPC/RC6 with acknowledged frequency bounds, Base/PowerSaving profiles and userspace policy replay; protected passive GuC log descriptors; cached DG2/BMG hwmon, fan/thermal readings and bounded DG2/BMG PL1 control | Full devcoredump and lossless GuC log streaming, autosuspend with live VRAM (mapping revocation/eviction) or an active iGPU panel (display power wells/DC states), D3cold, dynamic BMG MERT cap removal/L2-flush frequency coordination and media-GT power management |
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
| VM and memory | 18–25k | Fault-mode, long-running and CPU-address-mirror VMs; USERPTR invalidation (memory-layer MMU notifier); VRAM eviction and migration through copy-engine jobs (GPU clears/copies); DG2 64K VRAM pages and flat-CCS clears; small-BAR VRAM; VRAM PRIME/P2P |
| Engines | 10–15k | MTL media GT (own GuC instance, VCS/VECS, HuC load/auth); load-balanced and parallel queues |
| Reliability and observability | 8–12k | Full devcoredump beyond bounded first-error reports; lossless GuC log streaming; OA and EU-stall perf streams |
| Power | 5–8k | D3cold; autosuspend with live VRAM or a lit panel; dynamic MERT caps; BMG PMT energy and remaining hwmon controls |
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
device queries Mesa treats as fatal are served. PXP, the low-latency hint,
the state-cache perf fix, purgeable madvise and fault-reporting VMs are used
only when advertised, which NARF does not do. Scratch-page VMs, queue
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
| Compatibility dispatcher | Observed revision/DSS/EU/clock, scheduler-enabled discovery, readonly default SSEU copies and exact lookup/errno/refusal behavior | Native fixtures pass; production GuC cards still select Xe, legacy backend admission remains open |
| VM/address mirrors | USERPTR invalidation/MMU notifier, i915 GEM_USERPTR, fault-mode and long-running VMs, CPU address mirrors | Open; memory/VM dependency |
| Local-memory management | DG2 64 KiB pages and CCS clear; small-BAR/unmapped VRAM; eviction/migration and GPU clear/copy jobs; VRAM PRIME/P2P | Open; VM and copy-job dependencies |
| Client-free CCS reconfiguration | Card-lifetime primary/render leases; admin-gated asynchronous reset, all-engine startup proofs and fresh-epoch publication | Implemented; native fixtures pass |
| Engine scheduling | Load-balanced and parallel queues | Open; queue dependencies |
| Media GT | Independent firmware/wake/cache/CT owner, VCS/VECS scheduling and HuC loading/authentication | Open; separate GT lifecycle |
| Diagnostics/performance | Lossless GuC log streaming, full devcoredump, OA and EU-stall streams, remaining i915 perf/SSEU/parameter interfaces | Open; explicit ownership and disclosure bounds |
| Atomic display | Watermarks/DBUF/CDCLK/pcode, multi-pipe and bigjoiner, DSC and VRR, tiled/compressed buffers and additional planes | Open; modeset resource transactions |
| Output support | MTL external-display admission, Type-C/Thunderbolt PHY and alt mode, HDMI 2.1, DP UHBR, owned hotplug, qualified PSR2/panel replay | Open; per-platform display profiles |
| DSB color transactions | Fixed progressive MTL/Arrow Pipe-A active LUT replacement and joint CTM/gamma arms; retained WC command mapping, leaf status/readback completion and independent DMA retirement | Implemented; native fixtures pass |
| Display services | Display runtime PM/DC states/DMC, FBC, broader color profiles/transforms, HDCP and Arc display | Open; display/firmware dependencies |
| BMG package PL1 | Shared PCODE owner; passive firmware defaults, admin-gated pair-preserving write and exact current-source readback | Implemented; native fixtures pass |
| GT power/telemetry | D3cold, safe autosuspend with live mappings/panel, dynamic MERT/L2-flush coordination, media power, BMG PMT energy and writable fan/thermal controls | Open; mapping revocation and platform PM |
| Additional platforms | Gen12 GuC admission, Lunar Lake and Panther Lake profiles and their execution/display probes | Open; primary-source register/firmware contracts |

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
