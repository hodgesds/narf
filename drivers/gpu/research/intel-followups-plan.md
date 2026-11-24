# Intel GPU follow-ups: plan of work

Status: planned on `feat/intel-gpu-followups` (2026-11-23), cut from main
at `f1d42f6f2`. This note gives the order of work and the decisions it
rests on. Each lane lands its interface in `specification/spec.md` §3 and
its facts in `specification/intel_gpu.md`, as the Gen9 and Gen11 lanes
did.

## Decisions

- **Scope: everything listed.** That covers the Gen9 and Gen11
  remainders (§12.3, §12.4), the display gaps the spec names, every
  capability row still marked Open (§20 table), and the §6 out-of-scope
  programmes.
- **Comet Lake reads the PCI revision ID** (Q6). Revision 5 and above
  take the `cml_*` GuC and HuC blobs; older parts take Kaby Lake's, as
  `INTEL_REVID` selects in `gt/uc/intel_uc_fw.c`.
- **Same grounding bar as the earlier lanes.** Each register,
  sequence and table is checked against Linux i915/xe at the pinned
  revision, and native fixtures pin it. Nothing here has run on silicon,
  and each lane says so in the spec.
- **One branch, lane by lane.** Each commit gets a type-check and fmt.
  Clippy and the targeted QEMU suites run on both arches at the end.

## Lanes, in order

0. ~~**S4 gate leftovers.**~~ Freezer done; clippy and the stack-frame
   budget get re-checked at the final gate. The aarch64 `verification/freezer` failure:
   the own-stack model had no freeze point for a task running in user
   mode. The tick preemption resumes the continuation straight back to
   user mode, and the poll gate runs only on the first entry. Fix:
   `freeze_on_user_tick`, which each arch's IRQ tail calls after the
   tick's preemption. Main already fixed clippy (#2389, #2444) and the
   image-file stack frame (#2445); the final gate re-checks both.
1. ~~**Q6 Comet Lake revision.**~~ Done (`GtPlatform::guc_for_revision`,
   `huc::firmware_name_for_revision`, `open_for_revision`).
2. ~~**Gen9 pipe scaler and panel fitting.**~~ Done (`plan_display9`,
   `Modeset::set_gen9_panel_fit`). Ground `skl_scaler.c`'s
   display-9 branches: scaler count per pipe, the up/downscale and
   source-size limits, and the `PS_CTRL` filter and mode bits. Wire them
   into the Gen9 modeset the way `XeLpgModeset::with_panel_fit` does on
   display 14.
3. ~~**Gen11 Q8.**~~ Done: PORT_D pool arbitration, the 36-bit ceiling,
   the ICL Type-C FIA handshake plus TBT clocking, the FIA lane count, and
   USB-C DP alt mode on Ice Lake through the bridge.
   - EHL/JSL PORT_D: arbitrate the {DPLL0, DPLL1, DPLL4} pool per
     commit. PORT_D shares PHY A with PORT_A (`icl_get_combo_phy_dpll`,
     `ehl_combo_pll_div_frac_wa_needed`).
   - The EHL/JSL 36-bit PPGTT ceiling (`ppgtt_size = 36` in
     `i915_pci.c`): a three-level walk and the VM-range refusals.
   - Ice Lake TBT alt-mode and TCSS/FIA: the Type-C port ownership
     handshake, live mode detection (legacy, DP-alt, TBT), and TBT PLL
     routing through `DDI_CLK_SEL_TBT_*`. The TC code in
     `display/intel_tc.c` is the source; the ICL branches use no FIA
     HIP bank.
4. ~~**Gen11 and Gen9 external sessions.**~~ Done: DP/HDMI SST
   (`SourceFamily`, ICP and SPT hotplug banks, Gen11 and Gen9 DDC pins,
   the hotplug glue, the display 9-11 stop proof, per-source DP rate caps)
   and MST. Found on the way: the display 9-11 `TRANS_DDI_FUNC_CTL` port
   select. Thread the families through
   the session layer, which fails closed for them today: the
   `DpConnection`/`HdmiConnection` family fields, VRR gating (neither
   family has VRR), the DDC pin overrides, and the ICP and SPT/KBP
   south hotplug profiles. MST session threading follows, after SST works.
5. ~~**HDMI completeness.**~~ Done: DVI sinks, deep colour, YCbCr 4:2:0
   on display 11/12, and FRL through a DP PCON (i915 has no native FRL).
   4:2:0 on display 14 remains.
   - DVI signalling, with no infoframes or SCDC.
   - AVI and SPD infoframes for HDMI sinks.
   - YCbCr 4:2:0 and deep colour (10 and 12 bpc): EDID caps, the
     TMDS clock scaling, the `PIPE_MISC` and `TRANS_DDI_FUNC_CTL`
     bits.
   - Verify that the Xe-LPG text ("340 MHz, scrambling/SCDC not
     owned") still holds. The output-support row says MTL HDMI 2.0
     scrambling/SCDC reaches 594 MHz.
   - FRL last.
6. **Xe-LPG HDMI routing.** The hotplug service already selected HDMI
   (the spec text was stale). The SNPS C10 and computed C20 clocks are
   done. Type-C DDC on pins 9–12. HDMI clocks without a source table:
   the SNPS C10 algorithm and the computed C20 algorithm
   (`intel_snps_hdmi_pll.c`, `intel_cx0_phy.c`). TBT-alt stays refused
   until lane 3's TC ownership work is generalised.
7. **Multi-pipe modeset.** A second independent concurrent external
   route. This is the general watermark/DBUF/CDCLK transaction the
   atomic-display row names, beyond the fixed Pipe-A owner.
8. **Display 20/30 externals.** Lunar Lake and Panther Lake combo DDI B
   and HDMI, on the display-20 resources lane 7 generalises.
9. **Rocket Lake and Nova Lake-S display.**
   - RKL: its DPLL and clock sequence (`rkl_pll_mgr`, the
     `RKL_DPLL_CFGCR*` and `DPCLKA_CFGCR0` port mapping, the PCH-port
     DDI remap).
   - NVL-S: the clock/PHY/modeset policy the spec gates programming
     on.
10. **Capability rows still Open**, one sub-lane per row, in table
    order:
    - VM/address mirrors: i915 `GEM_USERPTR`, fault-mode and CPU-mirror
      VMs, long-running VMs.
    - Local memory: nonvisible allocation beyond BMG headless,
      eviction/migration, alias revocation, VRAM PRIME/P2P.
    - Engine scheduling: further queue protocols. Protected queues
      need PXP and so the MEI proxy.
    - Media GT: the MEI GSC proxy client.
    - Diagnostics: steered manual capture, coredump process/time facts.
    - Atomic display: what lane 7 leaves, plus tiling/compression beyond
      X/Tile4 and additional planes.
    - Display services: colour, HDCP, Arc display.
    - GT power: flush consumers, media power, D3cold where `_PR3`
      exists.
    - Additional platforms: LNL FBC, tiled panning, suspend/relight,
      and PTL display.
11. **The §6 programmes**, each its own grounding first:
    - Gen9-LP BXT/GLK, with the DPIO PHY.
    - Lunar Lake and Battlemage 3D.
    - Discrete Arc beyond bring-up.

    HDCP needs the same MEI/CSME client as PXP. The PUNIT blob stays
    excluded: it is firmware NARF does not load.

## Shared files

The display session layer (`intel_gpu_modeset.rs`, the hotplug service)
is Intel-only. Nothing here touches the AMD modules the Navi22 branch
works in. Any change outside `drivers/gpu/src/intel_gpu*` gets flagged
in the PR.
