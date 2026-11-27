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
| `narf.intel.gen9_irq=1` | Gen9 and Gen9 LP interrupt owner: MSI, hotplug-driven external pass, `intel_irq_suspend`/`resume` |
| `narf.intel.execlists_suspend=1` | Gen9/Gen11 execlists GT stopped for system sleep (drain, RPS/RC6 off, reset, `GT_IRQ` dropped) and brought up after |
| `narf.intel.pp_divisor=1` | `PP_DIVISOR` on display-9 panels with an SPT/KBP/CMP-V south display |
| `narf.intel.gen9_dpll=1` | Gen9 DPLL1-3 arbitration and sharing between external outputs |
| `narf.intel.rkl_edp=1` | The Rocket Lake internal panel on the owned eDP route |
| `narf.intel.dg1_kms=1` | The DG1 KMS owner over its firmware-lit Pipe A |
| `narf.intel.hdmi14_ext=1` | Display 14+ external deep colour, YCbCr 4:4:4 into a DP PCON, and HDMI/DP audio with its component |
| `narf.intel.svm=1` | Xe CPU-address-mirror VMs on fault-mode VMs of USM devices (LNL, PTL/WCL, NVL-S, BMG) |

## Still open

Each item needs its own grounding against Linux i915/xe first, as the landed
work had.

- Silicon runs of everything above, including the Gen9 display suspend
  owner (`narf.intel.gen9_suspend=1`) and Gen9 LP DC9.
- Nova Lake-S: DC3CO (a typed refusal until the route has a LOBF,
  panel-replay or PSR2 trigger and owns the CMTG; Panel Replay is qualified
  on display 20/30 only and never with the AS SDP its trigger needs, and
  the CMTG is not implemented), and silicon runs of the
  DC service and of a TBT dock. Thunderbolt alt mode on the LT PHY and the
  MST and DSC fixtures over LT ports have landed; the DMC wakelock is not
  used, and an inherited wakelock mode blocks DC6.
- Display 14 and later: deep colour, YCbCr 4:4:4 into a 4:2:0 PCON and
  HDMI/DP audio with the HDA driver's Intel HDMI codec on the audio
  component (`narf.intel.hdmi14_ext=1`), a second concurrent external
  route (`narf.intel.ext_routes=2`), Panel Replay on the display-20/30 eDP
  (`narf.intel.panel_replay=1`) and compressed scanout (`narf.intel.ccs=1`)
  have native fixtures only. Still open: their silicon runs, the HDA probe
  deferral when the display binds after the HDA controller, deep colour
  through a branch, UHBR, MST or DSC, MST audio, DP YCbCr 4:2:0, MST or
  UHBR beside a second route, Panel Replay on the external routes (their
  console scanout has no frontbuffer tracking to exit replay) and with the
  AS SDP, region early transport, and panned compressed views. Native HDMI
  FRL stays refused: Linux 7.4 has no source FRL link training (its rate
  and PHY facts are carried).
- DP 2.0 UHBR beyond the 128b/132b SST route behind `narf.intel.uhbr=1`
  (UHBR10/20 on C20 and LT ports, over display-30 Thunderbolt with DP
  tunnel BW allocation, through non-transparent LTTPRs, with the
  reduced-parameter retry, HDCP, the VBT C20 UHBR override, DSC over
  128b/132b SST with the Linux 7.4 DSC search, and 128b/132b MST; native
  fixtures only): DSC over 128b/132b MST, 128b/132b MST through a DP tunnel
  (per-stream tunnel bandwidth), the reduced-parameter retry for compressed
  and MST UHBR links, per-hop 8b/10b LTTPR training
  (`intel_dp_link_train_all_phys`), the VBT DP 1.4 C20 and C10 overrides,
  and a silicon run.
- Older display: the Gen9 interrupt owner (`narf.intel.gen9_irq=1`), the
  execlists GT across system sleep (`narf.intel.execlists_suspend=1`),
  `PP_DIVISOR` on pre-CNP south displays (`narf.intel.pp_divisor=1`), Gen9
  DPLL1-3 arbitration between external outputs (`narf.intel.gen9_dpll=1`),
  the Rocket Lake internal panel (`narf.intel.rkl_edp=1`) and a DG1 KMS
  owner (`narf.intel.dg1_kms=1`) have native fixtures and no silicon run.
  Still open there: Gen9 pipe B/C interrupts once PW_2 comes up after the
  install (`gen8_irq_power_well_post_enable`), vblank, flip-done and
  underrun consumers, PSR (PSR1; PSR2 is defeatured, Wa_16011181250) and a
  KMS presenter on the Rocket Lake panel, and the DG1 presenter (refused,
  as DG2's is, by the integrated Gen12 primary owner).
- PXP: protected planes decrypt or go black in every layout the plane
  takes (CPU and DSB arms), and the runtime wiring, the RUN_ALONE value and
  a protected queue's LRC through the GuC model have native fixtures; open
  are the KMS CPU-copy path for protected frames (refused) and a silicon
  run.
- HDCP: Gen9/Gen11 use the port-indexed registers (pcode key load on Gen9
  big core, MEI HDCP 2.2 on Kaby/Coffee/Comet Lake and Gen11, the MEI
  driver claiming the SPT, KBP, CNP-LP, ICP, JSP and MCC PCHs with
  `narf.intel.hdcp=1`) with Gen9/Gen11 MST fixtures, and the per-connector
  debugfs files exist; open is a silicon run (the NUC12's GOP-lit route is
  the first target). The firmware-lit Gen12 route has no hotplug owner, so
  its HDCP 2.2 waits still poll RxStatus every 10 ms: CP_IRQ there needs
  the HDCP service to own that display's hotplug (SDE latches and acks,
  what a long pulse does to a route NARF did not light), which is not a
  small change.
- VRAM PRIME/P2P beyond `intel_gpu_prime` (dynamic move-notify
  importers, peer-to-peer LMEM BAR mapping behind
  `narf.intel.prime_p2p=1`, migration fallback, in-place suspend of a
  pinned VRAM export, import mmap through the exporter, integrated-display
  scanout of an import, the `xe_dma_buf_begin_cpu_access` migration for
  CPU reads, and migration of an export a process has mmapped behind
  `narf.intel.prime_mmap_migrate=1`): AMD exporters and importers, a
  mapped DG2 export's move (its Flat-CCS needs the GPU copy the alias
  freeze cannot await), and validation of the P2P, suspend and migration
  paths on hardware.
- CPU-address-mirror VMs behind `narf.intel.svm=1`: routing hardware GPU
  faults to the fault service (ASIDs, the GuC G2H 0x6002 path, updating a
  running job's tables), VRAM migration (`drm_pagemap`) on Battlemage,
  madvise, and a silicon run.
- D3cold through `_PR3` power resources (NARF evaluates no AML).
