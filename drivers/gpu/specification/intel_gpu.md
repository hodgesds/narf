# drivers/gpu/intel_gpu — Specification

> Status: **v0.8** (Stage 1 + Stage 2 codecs landed; lane 1
> #1010: canonical device table + census, panic-free probe with
> owned contiguous scanout, Gen12 display gate; Stage 5 RCS0
> command submission landed — see §8; PPGTT walker + GGTT
> bounds/flush discipline landed — see §9; external DisplayPort
> full single-stream landed — see §10).
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
| pantherlake (Xe3-LPG) | B080, B081, B082, B083, B084, B085, B086, B087, B08F, B090, B0A0, B0B0 |

Note: pci.ids labels 46B0/46B1/46B3 as AlderLake-P silicon; the
driver has always classified them `raptorlake-p` and the census
pins that existing behaviour (re-classification is out of scope
for lane 1).

A single class-match backstop (`MatchKind::Class { class: 0x03,
mask: 0xFF }`) catches every PCI VGA controller; the probe body
filters on `vendor == 0x8086` so AMD / NVIDIA / virtio-gpu cards
fall through to their own drivers. An Intel DID outside the
table is announced on the console as an unsupported ASIC and the
probe returns `NotForThisDriver` — it no longer collapses
silently into the same `BadDevice` used for dead hardware.

Display programming is gated to Gen12 (Tiger Lake / Alder Lake /
Raptor Lake). Meteor Lake and Panther Lake rows identify and
announce only; their display engines are tracked in #1016.

## 6. Out of scope

- **Gen9 (Skylake / Kaby Lake / Coffee Lake) and Gen11 (Ice
  Lake / Jasper Lake / Elkhart Lake)** — explicitly out of scope.
  No device IDs are listed for them and none will be added to
  this driver: the codec layer is Gen12-shaped (combo-PHY DPLL,
  universal planes), so those generations would need a separate
  display model, not more table rows.
- Arrow Lake identification (7D41 / 7D51 / 7D67 / 7DD1 in
  pci.ids) — not yet listed; tracked as a follow-on to lane 1.
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
- **Watermarks / DBUF allocation** — the PRM's "Display Buffer
  Allocation and Watermark Programming Prior to OS Boot" basic
  programming: 160 DBUF blocks to Pipe A's primary plane,
  level-0 watermark 160 blocks / 2 lines, higher levels off.
  The full latency-based algorithm (pcode mailbox latencies)
  and DBUF_CTL power-request sequencing remain follow-on work.
- **DDI_BUF_TRANS** — the modeset loads the swing table for
  the training start rate before link training and reloads if
  training settles elsewhere. RBR/HBR resolve to the HBR2 table
  (see `intel_gpu_ddi` for the rationale).
- **PLL table corrected** — DPLL_CFGCR0/1 field layouts and the
  four DP coefficient rows now match TGL PRM Vol. 12's
  "DisplayPort Mode PLL Values" for the 19.2/38.4 MHz reference
  family (DCO 8100 MHz for all rates; P/K per rate). The 24 MHz
  family shares the dividers with int 0x151 / frac 0x4000;
  DSSM reference-frequency selection is not yet implemented.
- **PLANE_CTL format pinned** — source-format discriminants
  corrected to the ICL+ 5-bit field values (XRGB_8888 =
  0b01000); fixture-pinned against PRM Vol. 14.
- **Publication** — a probed Gen12 scanout is published to the
  framebuffer console through the same ACTIVE + observer
  protocol the AMD display pipeline uses, and the DRM card
  carries real KMS mode state (CRTC 1, encoder 2 TMDS,
  connector 3 eDP) instead of the identity stub.

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


## 10. External DisplayPort, full single-stream (lane Q4 — `intel_gpu_dp`, #1092)

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
- The PLL table is complete for both PRM reference families:
  19.2/38.4 MHz (DCO int 0x1A5, frac 0x7000) and 24 MHz
  (int 0x151, frac 0x4000), divider fields identical per rate
  (RBR P/5 K/2, HBR P/3 K/2, HBR2 P/3 K/1, HBR3 P/2 K/1), all
  rows fixture-pinned. Reference-family *selection* via DSSM
  remains #1024; the resolver defaults to the 19.2/38.4
  family, as before.
- Audio is published only when the sink's CTA extension
  carries at least one SAD; a sink without audio gets video
  only, and disconnect always clears the publication before
  the pipeline comes down.

Deliberate remainders: DP MST and multi-pipe (#1017),
Xe-LPG display (#1016), Type-C HPD via the GEN11 DE HPD block
(the Alt-Mode bridge's DDIs), DSC/FEC, and the HPD IRQ
handler itself (interrupt enables are programmed; the
session is poll-driven until an IRQ consumer lands).

## 11. External HDMI, full (lane Q5 — `intel_gpu_hdmi`, #1019)

The external-HDMI path for combo DDIs, Gen12. Compiled
only under the gpu crate's `intel` feature. Sources: HDMI
1.4 §5.3.5 and CTA-861 infoframe packing (as implemented
by Linux `drivers/video/hdmi.c`), HDMI 2.0 §10 (SCDC; the
register map as carried by `drm_scdc_helper.h`), TGL PRM
Vol. 2c (TRANS_DDI_FUNC_CTL HDMI bits), Vol. 11 (WRPLL —
the `cnl_ddi_calculate_wrpll` search i915 uses for HDMI on
CNL and ICL+), Vol. 12 (DIP banks, AUD_CONFIG), CEA-861-D
§7.5 (ELD, via the §10 sink).

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
`cnl_hdmi_pll_ref_clock`). Rows are fixture-pinned with an
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

Audio consumes the §10 **shared display-audio sink** as
second publisher (`DisplayConnector::Hdmi`; same sink id
per physical connector — DDI index + 1 — because a
connector is either DP or HDMI at a time). The codec side
is the HDMI branch of `intel_gpu_audio`: AUD_CONFIG
carries the PRM pixel-clock code for the TMDS clock and
latches with N_PROG_ENABLE only (no DP timestamp mode, no
N_VALUE_INDEX — the disable path conditions that bit on
the old configuration being DP, so the HDMI disable omits
it too). Publication order matches §10: ELD into the sink
first, codec enable, then ELD_VALID. The cross-vendor
display-audio story is tracked in #778 (AMD), referenced
not closed by this lane.

HPD is the §10 GEN8 DE Port block, shared: HDMI sinks
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
