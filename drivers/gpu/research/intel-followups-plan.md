# Intel GPU follow-ups

Status: the plan cut from main at `f1d42f6f2` (2026-11-23) has landed, in
#2489 (`feat/intel-gpu-followups`) and #2511 (`feat/intel-gpu-remaining`).
The facts are in `specification/intel_gpu.md` and the interfaces in
`specification/spec.md` §3. Native fixtures, not silicon, validate the work.

## Landed

- #2489: Comet Lake GuC/HuC by PCI revision; Gen9 panel fitting; EHL/JSL
  PORT_D PLL arbitration and 36-bit VMs; Ice Lake Type-C ownership, TBT
  clocking, FIA lane count and USB-C DP alt mode; Gen11 and Gen9 external
  DP/HDMI SST and MST; HDMI to DVI sinks, deep colour, YCbCr 4:2:0 on display
  11 to 20, and FRL through a DP PCON; computed SNPS C10 and C20 HDMI clocks
  on Meteor Lake; concurrent Gen12 external routes; Lunar and Panther Lake
  combo DDI B DP and HDMI; Rocket Lake externals on DDI B and TC1/TC2; the
  Gen9/Gen11 execlists GT owner with the golden render state; the GT started
  beside lit discrete and desktop displays; DG1 VRAM.
- #2511: Lunar Lake panel PHY/AUX in the PICA block; Gen9/Gen11 RPS and RC6,
  per-engine reset, copy and media engines, timeslicing and priority
  preemption on the execlists owner; fixed-mode KMS on Meteor/Arrow Lake,
  Gen9 and Gen11 desktops; devcoredump wall-clock time and process names;
  Broxton/Gemini Lake GT and display (DPIO PHY, CDCLK, port PLLs, eDP,
  DP/HDMI, VBT HPD invert and backlight controller, HDMI PLL holes, Gemini
  Lake YCbCr 4:2:0); Nova Lake-S display 35 (`DisplayIp::NovaLakeS`, the
  owned eDP modeset through the LT PHY, suspend relight, external
  DP/HDMI/DP-alt on the LT PHY, DMC/DC6); and the opt-in features below. The
  MEI GSC proxy client had landed before.

Boot options, each strict and default off:

| Option | Enables |
| --- | --- |
| `narf.intel.nvl_display=1` | Nova Lake-S display 35 kept lit as fixed-mode KMS beside a display-preserving GT |
| `narf.intel.nvl_modeset=1` | With `nvl_display`: the owned eDP route, its relight, the LT externals and DC6 |
| `narf.intel.gen9_dc=1` | Gen9 and Gen9 LP DC states; DC9 across suspend on Gen9 LP with the display dark |
| `narf.intel.prime_p2p=1` | Peer-to-peer VRAM PRIME attachments |
| `narf.intel.pxp=1` | Xe PXP on MTL/Arrow GT1 (with `media_gt=1` and `gsc=1`) |
| `narf.intel.hdcp=1` | HDCP 1.4 and 2.2 on external SST DP and HDMI, display 12+ |

## Still open

Each item needs its own grounding against Linux i915/xe first, as the landed
work had.

- Silicon runs of everything above. The Gen9 DC states also need a Gen9
  display suspend owner that turns the panel off and relights it (a lit
  panel keeps DC9 refused), `intel_cdclk_init_hw` and the PCH reset
  handshake on resume, BXT DSI transcoders in the dark-display check, and
  `assert_can_enable_dc9`'s interrupts-off check.
- Nova Lake-S: Thunderbolt alt mode on the LT PHY, Nova fixtures for
  MST and DSC over LT ports, DC3CO (it needs the CMTG and a LOBF,
  panel-replay or PSR2 trigger) and the DMC wakelock (`intel_dmc_wl`).
- Display 14 and later: native HDMI FRL, HDMI audio, deep colour and
  YCbCr 4:4:4, a second concurrent external route, panel replay, and
  compressed primary layouts.
- DP 2.0 UHBR beyond the 128b/132b SST route behind `narf.intel.uhbr=1`
  (UHBR10/20 on C20 and LT ports, native fixtures only): 128b/132b MST, DSC
  over UHBR, UHBR over Thunderbolt alt mode (TBT 312.5/625 MHz clocks, DP
  tunnel BW allocation), LTTPR non-transparent mode, the reduced-parameter
  retry after a failed 128b/132b training, HDCP on 128b/132b, VBT C20
  vswing overrides, and a silicon run.
- Older display: the Rocket Lake internal panel, a DG1 KMS owner, Gen9
  DPLL arbitration between two external outputs, and the Gen9 interrupt
  handler (`intel_gpu_gen9_irq` has no caller).
- PXP: protected planes decrypt or go black on linear XR24 only (tiled and
  XR30 protected framebuffers are refused), the RUN_ALONE LRC bit and the
  runtime wiring have no native model, and there is no silicon run.
- HDCP: the Gen9/Gen11 port-indexed HDCP registers, the debugfs files,
  HDCP on 128b/132b links, and a silicon run (the NUC12's GOP-lit route is
  the first target). The firmware-lit Gen12 route has no hotplug owner, so
  its HDCP 2.2 waits still poll RxStatus every 10 ms.
- VRAM PRIME/P2P beyond `intel_gpu_prime` (dynamic move-notify
  importers, peer-to-peer LMEM BAR mapping behind
  `narf.intel.prime_p2p=1`, migration fallback, in-place suspend of a
  pinned VRAM export, import mmap through the exporter, integrated-display
  scanout of an import): AMD exporters and importers, the
  `xe_dma_buf_begin_cpu_access` migration to system memory for CPU reads,
  and validation of the P2P and suspend paths on hardware.
- CPU-address-mirror VMs.
- D3cold through `_PR3` power resources (NARF evaluates no AML).
