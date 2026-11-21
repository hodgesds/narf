# Raphael (GC 10.3.6) graphics port map

Raphael (`1002:164E`) is an RDNA2 APU. Its display path is
`raphael-dcn315-port.md`; this file is about graphics: GFX, SDMA, the memory
hubs, interrupts and the firmware that runs them. Media (VCN/JPEG 3.1.2) comes
last.

Source: Linux `v7.3-rc4` in `/usr/src/linux`. Every claim below cites the file
it came from.

## Starting point

NARF's only working graphics bring-up is the discrete RDNA2 cold boot,
`amdgpu_navi22_boot::ColdBoot` (Navi21–24, GC 10.3.0/2/4/5). It runs 31 stages
over Navi22-named backends (`amdgpu_{gmc,sdma,ih,cp,kiq,fence,vcn}_navi22`),
each of which resolves its chip through `amdgpu_rdna2::for_pci_id`. Phoenix has
no graphics bring-up: `load_firmware_multi` refuses it.

Raphael runs the same Linux graphics blocks as Navi22 — `gfx_v10_0`,
`sdma_v5_2`, `navi10_ih`, `gmc_v10_0` with `gfxhub_v2_1` — but as an APU:

| | Navi22 (discrete) | Raphael (APU) |
|---|---|---|
| GC | 10.3.2 | 10.3.6 |
| PSP (MP0) | 11.0.11, SOS loaded by the driver | 13.0.5 (`psp_v13_0`), SOS BIOS-resident; TOC + TA only |
| SMU (MP1) | 11.0.x, SMC loaded, PowerPlay table | 13.0.5 (`smu_v13_0_5_ppt.c`), PMFW BIOS-resident |
| SDMA | 5.2.2, two engines | 5.2.6, one engine |
| MMHUB | 2.1.0 (`mmhub_v2_0`) | 2.3.0/2.4.x (`mmhub_v2_3`) |
| NBIO | 2.3 (`nbio_v2_3`) | 7.2/7.3/7.5 (`nbio_v7_2`), see below |
| HDP | 5.0.x | 5.2.1 (`hdp_v5_2`) |
| Memory | trained GDDR6 behind a BAR | the BIOS carve-out |

## What GC 10.3.6 changes in `gfx_v10_0.c`

In every `gfx_v10_0.c` switch that names 10.3.6, it sits in the Sienna Cichlid
(10.3.x) group alongside Navi22, except:

- `gfx_v10_0_init_golden_registers`: its own `golden_settings_gc_10_3_6`
  (22 rows) and nothing else.
- `gfx_v10_0_setup_rb` and `gfx_v10_0_get_cu_info`: shader arrays disabled in
  `gfx_v10_3_get_disabled_sa` are skipped (10.3.6 and 10.3.7 only).
- `gfx_v10_0_check_grbm_cam_remapping`: the APU group (10.3.1/3/6/7) always
  remaps, without probing `VGT_ESGS_RING_SIZE`.
- `gfx_v10_cntl_power_gating` / `gfx_v10_0_set_powergating_state`: the APU
  group programs `RLC_PG_DELAY_3` and drives GFXOFF through
  `amdgpu_gfx_off_ctrl`.
- `gfx_v10_0_get_gpu_clock_counter`: SMUIO `GOLDEN_TSC_COUNT_*_GC_10_3_6`.
- `gfx_v10_0_sw_init`: the 10.3.0 cleaner shader (not used by NARF).

`gfx_v10_0_set_rlc_funcs` gives it `gfx_v10_0_rlc_funcs`, as Navi22.
`nv_common_early_init` gives it the APU cg/pg set (GFX PG, VCN DPG, JPEG PG,
plus FGCG and MGLS, which Navi22 lacks).

## Other blocks

- **Reset**: `nv_need_reset_on_init` returns false for every APU.
- **PSP 13.0.5**: `psp_v13_0` with `boot_time_tmr = false`;
  `autoload_supported` keeps its default, so the non-PSP firmware load ends
  in `psp_rlc_autoload_start` as on Navi22. No runtime DB on an APU
  (`psp_get_runtime_db_entry`), no TOS reload. The ring, TOC and TMR are
  already done (display step 9).
- **SMU 13.0.5**: the graphics mailbox is `MP1_C2PMSG_2/33/34`. Its offsets
  (`0xbee142 + 0xb00000 / 4`) are past the MMIO BAR, so Linux's RREG32 goes
  through NBIO `PCIE_INDEX2/DATA2`, the same SMN route the display clock
  manager already takes to `MP1_C2PMSG_3`. `smu_hw_init` on an APU loads
  nothing and powers VCN and JPEG up and enables GFX CGPG.
- **GMC**: `gmc_v10_0_mc_init` gives the APU group a 1 GiB GART ("DCE SG
  support"). The hubs are `gfxhub_v2_1` (as Navi22) and `mmhub_v2_3` (new).
- **IH**: `navi10_ih` for OSSSYS 5.0.x/5.2.x; under PSP loading the ring uses a
  GPU address on both (`navi10_ih_sw_init`), so Navi22's VMID0 ring carries
  over. `ih_control` is NBIO's, so it differs.
- **SDMA 5.2.6**: `sdma_v5_2`, no golden table, one engine.

## Who owns the PSP

On Navi22 the cold boot owns the PSP ring and loads DMCUB with the graphics
firmware (Linux order: SDMA, CE, PFP, ME, MEC, MEC2, RLC, VCN, DMCUB), then
starts DMUB (`Stage::DmubStart`). On Raphael today, `amdgpu_platform` owns
the ring and loads only the TOC and DMCUB. The plan follows Linux:
- one coordinator owns the PSP;
- it loads every non-PSP firmware in UCODE_ID order and starts the RLC
  autoload;
- the display path then takes the DMCUB it loaded.

Until that coordinator is armed, the display path keeps its own PSP session,
as now.

## Order of work

1. ~~Identity: `amdgpu_rdna2::RAPHAEL`, a profile that `for_pci_id` never
   returns, so no discrete path admits it; `golden_settings_gc_10_3_6`~~
   (done).
2. ~~PSP: load the graphics bundle on the PSP 13.0.5 ring and wait for the RLC
   autoload~~ (done).
   - `gfx::Firmware::open_raphael` prepares the set under Raphael's names,
     bounded to GC 10.3.6, MP1 13.0.5, SDMA 5.2.6, DCN 3.1.5 and one VCN
     3.1.2 instance.
   - Raphael's containers match Navi22's formats: CP and RLC declare GC 10.3,
     SDMA 5.2, VCN 3. The RLC header is v2.2 where Navi22's is v2.4.
   - `dcn_3_1_5_dmcub.bin` declares DCN 3.1, so the DMCUB identity is now
     checked against the profile's DCN rather than DCN 3.0's.
   - The Raphael PSP session treats PMFW as resident: an SMC upload is refused,
     and the graphics set goes up after the TMR alone. The RLC autoload wait
     reads GC 10.3's `CP_STAT` and `RLC_RLCS_BOOTLOAD_STATUS`.
   - Nothing calls the load yet. That is the coordinator (step 8).
3. ~~SMU 13.0.5 graphics mailbox over SMN: versions, the driver interface
   check, GFXOFF control, VCN/JPEG power~~ (done, `amdgpu_smu_raphael`).
   - `MP1_C2PMSG_2/33/34` are SMN 0x3b10508/0x3b10984/0x3b10988 with MP1
     segment 0 at 0x16000; the constructor refuses any other base.
   - `start` checks `MP1_FIRMWARE_FLAGS.INTERRUPTS_ENABLED` (SMN 0x3b10024),
     then sends GetDriverIfVersion with no pre-poll (`SMU_FW_INIT`) and
     GetSmuVersion. A driver interface other than 5 is recorded, not refused,
     as Linux only logs it.
   - Rejections carry the firmware's status; an unknown response marks the
     firmware hung (`SMU_FW_HANG`), and nothing more is sent.
   - The NBIO `PCIE_INDEX2/DATA2` latch is now one lock (`amdgpu_smn`, Linux's
     `adev->reg.pcie.lock`) shared with the display clock manager's message
     write. Before, it was only a safety contract.
4. ~~NBIO 7.2: doorbell apertures, `ih_control`, the HDP flush register~~
   (done, `amdgpu_nbio_v7_2`).
   - Raphael's NBIO is `nbio_v7_2`'s. Discovery gives that driver 7.2.0,
     7.2.1, 7.3.0, 7.5.0 and 7.5.1, all from `nbio_7_2_0_offset.h`. Linux
     supported GC 10.3.6 (February 2022) before `nbio_v7_7` existed (May
     2022, added with SOC21's PCIe-port helpers). The PSP and SMN rows now
     accept all five; 7.7 stays only where its offsets are the same.
   - On segment 2 every NBIO register the RDNA2 backends program keeps its
     NBIO 2.3 offset and masks: doorbell aperture enable 0xc0, self-ring
     0xf3..0xf5, `INTERRUPT_CNTL`/`2` 0xf1/0xf2, HDP flush req/done
     0x106/0x107 and its CP0/CP2/SDMA0 bits, HDP remap 0x12d.
   - Only the doorbell ranges move: IH, SDMA0 and VCN0 become GDC0 registers
     (0x4f0af2/0x4f0af0/0x4f0af3 on segment 3) reached through the PCIe port
     pair (`RSMU_INDEX/DATA`, segment 1). `amdgpu_smn` holds the same lock
     around it, as Linux does. The field layout is unchanged.
   - `dcn315_resource.c` gives Raphael's NBIO segments: 0x0, 0x14, 0xd20,
     0x10400, 0x241b000, 0x4040000.
5. ~~GMC: `gfxhub_v2_1` on 10.3.6, `mmhub_v2_3`~~ (done, `Gmc::new_raphael`).
   The GART stays 512 MiB: a LINUX-GAP, since NARF's display does not scan
   out of GTT. What it took, against `amdgpu_gmc_navi22`:
   - **MMHUB 2.3 programming is MMHUB 2.0's.** A body-by-body diff of
     `mmhub_v2_3.c` against `mmhub_v2_0.c` differs only in RLC-routed against
     plain writes and SR-IOV branches. The register table is different:
     every register is on `_BASE_IDX` 1, most are +128 dwords, and the
     per-context and per-engine registers are interleaved. Context 1's
     page-table base is 8 dwords after context 0's (MMHUB 2.0: 2), and
     invalidation engine *n*'s REQ and ADDR_RANGE are 8 dwords apart (2.0: 1
     and 2). NARF's global `CTX_ADDR_DISTANCE` and the `inv_range + index * 2`
     stride become per-hub fields, an `amdgpu_gmc_navi22` change.
   - **HDP 5.2** has no `init_registers` and no invalidate. Its flush is the
     generic one NARF already does: write the 0x7f000 remap hole, then read
     MEMSIZE.
   - **NBIO 7.2 `init_registers`** sets `CI_SWUS_MAX_READ_REQUEST_SIZE_MODE/PRIV`
     to 1 in a port register on segment 5: `PCIE_CONFIG_CNTL` (0x420011) on
     7.2.0, `BIF1_PCIE_MST_CTRL_3` (0x4601c6, `nbio_v7_2.c`'s own define) on
     7.2.1/7.3.0/7.5.0. 7.3.0 and 7.5.1 also clear `STRAP_NO_SOFT_RESET_DEV2_F0`
     in `RCC_DEV2_EPF0_STRAP2` (0xd802, segment 5, SMN). Navi22 writes
     `smnPCIE_CONFIG_CNTL` through PCIE_INDEX2/DATA2 instead, without the
     shared lock; on Raphael the display worker shares the latch, so this goes
     through `amdgpu_smn`.
   - **APU GMC** (`gmc_v10_0_mc_init`): VRAM is MEMSIZE as on Navi22, the GART
     is 1 GiB for the APU group ("DCE SG support"; NARF's discrete GART is the
     512 MiB default), and Linux's x86_64 CPU access goes through the carve-out's
     physical address instead of the BAR, where NARF's pool keeps its own
     mapping.
6. ~~IH on NBIO 7.2~~ (done, `Ih::new_raphael`).
   - `navi10_ih` reads `osssys_5_0_0_offset.h` for every OSSSYS revision it
     drives (5.0.x, 5.2.0, 5.2.1). Its only version branches are the
     self-interrupt wptr update (5.0.3 and up) and `IH_CHICKEN` (direct
     firmware load only), so Raphael's OSSSYS keeps Navi22's registers.
   - NBIO 7.2 keeps `INTERRUPT_CNTL`/`2` and the HDP remap on segment 2. The
     ring's doorbell range (released, as NARF polls its rptr through
     `IH_RB_RPTR`) is GDC0's, through the port pair.
   - HDP 5.2.1 has no read cache: no `HDP_READ_CACHE_INVALIDATE`, and no
     cache fields left in `HDP_MISC_CNTL`. The ring is read through BAR0
     without an invalidate.
   - NARF's discovery parser kept only five base addresses per IP. Raphael's
     NBIO has six segments (`dcn315_resource.c`), and Linux keeps every one,
     so the cap is now the parser's own bound of 16.
7. GFX setup and topology (disabled shader arrays, CAM remapping), CP, KIQ,
   compute and GFX rings, SDMA 5.2.6 queues, IB tests and fences. Against
   the Navi22 backends:
   - **CP layout** (`amdgpu_cp_navi22::Layout`) gets a Raphael resolution:
     GC 10.3.6, the NBIO 7.2 segment-2 bank (the doorbell aperture,
     self-ring and HDP flush req/done keep their NBIO 2.3 offsets), OSSSYS
     5.0.x/5.2.x for the IH VMID LUT, and the 10.3.6 golden table.
   - **HDP invalidates.** HDP 5.0's `HDP_READ_CACHE_INVALIDATE` is written by
     the CPU before reading fences and results, and emitted as a WREG into
     rings and IBs (`amdgpu_navi22_submit`). HDP 5.2 has none:
     `hdp_v5_2_funcs` has no `invalidate_hdp`, so `amdgpu_hdp_invalidate`
     emits nothing, and Raphael drops them. Watch packet sizes wherever a
     frame is sized up front.
   - **GRBM CAM remapping** (`gfx_v10_0_check_grbm_cam_remapping`): the APU
     group (10.3.1/3/6/7) returns true without probing `VGT_ESGS_RING_SIZE`,
     so Linux never programs the CAM there. Raphael skips the probe and the
     setup.
   - **Topology**: `gfx_v10_3_get_disabled_sa`'s whole-SA skip applies to
     10.3.0/3/6/7 (NARF has only 10.3.0). `RCC_DEV0_EPF0_STRAP0` is 0x11 on
     NBIO 7.2.0, as on 2.3, but `nbio_v7_2_get_rev_id` reads the `_YC`
     variant (0x15) on 7.2.1/7.3.0/7.5.0.
   - **SDMA 5.2.6**: one engine, and NBIO 7.2 has a single SDMA doorbell range
     (GDC0, through the port pair) where NBIO 2.3 has one per engine.
   - KIQ and fences touch no NBIO or HDP register.
8. ~~The APU cold-boot coordinator and the PSP handover from the display
   path~~ (done, `amdgpu_raphael_boot`).
   - **PSP handover.** The display path keeps the one PSP session.
     `amdgpu_platform` hands its loader Raphael's graphics set
     (`Loader::set_graphics`), and its PSP boot loads every non-PSP firmware
     in `psp_load_non_psp_fw` order (SDMA, CE, PFP, ME, MEC, MEC2, RLC with
     its autoload, VCN, DMCUB). It then waits for the RLC boot, in place of
     DMCUB alone. The set's DMCUB payload must be the signed instructions the
     loader validated. `amdgpu.rdna2_accel=0`, or a set that cannot be
     opened, keeps the display-only load.
   - **Coordinator.** After DMUB boots, `ColdBoot` runs once on the display
     pool:
     - SMU start and `DisallowGfxOff`;
     - GMC and GART, then IH;
     - golden settings, then the SDMA0 proof and its trap round trip;
     - doorbells, GFX setup, KIQ, compute and GFX rings, SDMA queues;
     - IB tests, fence interrupts, topology.

     Each engine is its discrete owner's Raphael resolution. A failure stops
     there and leaves the display as it is; the owners are retained.
   - **Suspend.** After a graphics boot, the loader refuses to stop, so
     suspend is refused. Releasing the TMR needs the RLC and CP that run from
     it reset, and no Raphael graphics reset or resume exists yet.
   - Not done: publishing acceleration to userspace (INFO/render node), any
     GFXOFF or power-gating policy (GFX stays powered), and suspend/resume.
9. Media: VCN and JPEG 3.1.2.

## Open

- Raphael's exact NBIO, MMHUB and OSSSYS revisions come from a discovery table
  nothing here has read; NBIO is inferred to be `nbio_v7_2`'s from Linux's
  history (step 4).
- PMFW's initial GFXOFF state on 13.0.5: Linux starts with a GFXOFF request
  count of 1 (disallowed) and never sends `DisallowGfxOff` at init.
