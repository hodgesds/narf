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
| NBIO | 2.3 (`nbio_v2_3`) | 7.2 (`nbio_v7_2`) or 7.7 (`nbio_v7_7`) |
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

1. Identity: `amdgpu_rdna2::RAPHAEL`, a profile that `for_pci_id` never
   returns, so no discrete path admits it; `golden_settings_gc_10_3_6`.
2. PSP: load the graphics bundle on the PSP 13.0.5 ring and wait for the RLC
   autoload.
3. SMU 13.0.5 graphics mailbox over SMN: versions, the driver interface check,
   GFXOFF control, VCN/JPEG power.
4. NBIO 7.2/7.7: doorbell apertures, `ih_control`, the HDP flush register.
5. GMC: `gfxhub_v2_1` on 10.3.6, `mmhub_v2_3`, a 1 GiB GART in the carve-out.
6. IH on NBIO 7.x.
7. GFX setup and topology (disabled shader arrays, CAM remapping), CP, KIQ,
   compute and GFX rings, SDMA 5.2.6 queues, IB tests and fences.
8. The APU cold-boot coordinator and the PSP handover from the display path.
9. Media: VCN and JPEG 3.1.2.

## Open

- Raphael's exact NBIO, MMHUB and OSSSYS revisions come from a discovery table
  nothing here has read.
- PMFW's initial GFXOFF state on 13.0.5: Linux starts with a GFXOFF request
  count of 1 (disallowed) and never sends `DisallowGfxOff` at init.
