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
9. ~~Media: VCN and JPEG 3.1.2~~ (done, `ColdBoot::run_media`).
   - `amdgpu_discovery.c` gives VCN 3.1.2 `vcn_v3_0` and `jpeg_v3_0`,
     Navi22's drivers, on `vcn_3_0_0_offset.h`. Their 3.1.2 branches are:
     - `fw_shared->smu_interface_info.smu_interface_type = 2` (byte 88 of
       `amdgpu_fw_shared`, after the 4-aligned `fw_log`);
     - no `CC_UVD_HARVESTING` read in `jpeg_v3_0_early_init`;
     - the Yellow Carp decode table (not published yet).
   - VCN is power gated until PMFW gets `PowerUpVcn`, and JPEG `PowerUpJpeg`.
     Linux's APU `smu_hw_init` sends both; `run_media` sends them before VCN
     starts, so a media failure leaves graphics up.
   - DPG start as on Navi22 (`AMD_PG_SUPPORT_VCN_DPG` is in 10.3.6's
     pg_flags). The register lists go through the display loader's PSP
     session, the one that loaded VCN.
   - NBIO 7.2's single GDC0 VCN0 doorbell range (SIZE 8) through the port
     pair serves VCN and JPEG, where NBIO 2.3 has MMSCH ranges.
   - Frame budget: the layouts every register access copies stay their
     discrete size (the HDP option is a `NonZeroU64`). NBIO 7.2's banks live
     in the owners, not the layouts, and the coordinator boxes its owners.

## Publishing to userspace

Navi22 publishes acceleration through four modules that the discrete
`for_pci_id` table and Navi22's cold-boot owner gate:
- `amdgpu_info_navi22` (INFO replies);
- `amdgpu_navi22_cs` (the `amdgpu_cs::Submitter`, client VMIDs, the visible
  VRAM heap);
- `amdgpu_rdna2_vram` (hidden-VRAM transfers);
- `amdgpu_vcn_navi22_cs` (media rings).

Raphael's coordinator holds the same engine owners (`cp::Gfx`,
`kiq::Compute`, `sdma_queues::Sdma`, `vcn::Media`, `gmc::Gmc`), inside the
display owner beside the PSP session that loaded them. So the work is to
route those modules to it, not to write a second client backend.

10. Publish acceleration:
    1. ~~Fence wakes~~ (done). The FenceInterrupts stage subscribes the CP EOP, SDMA0
       trap and CP fault sources through Navi22's `route_fences`, so client
       fences wake on interrupts. Without that they wait out the throttle
       deadline.
    2. ~~Identity~~ (done). INFO answers Raphael through `amdgpu_info_navi22` with
       `amdgpu_kms.c`'s APU rules:
       - `AMDGPU_FAMILY_GC_10_3_6`;
       - chip_rev from `nbio_v7_2_get_rev_id`, external_rev = rev + 1
         (`nv_common_early_init`);
       - `AMDGPU_IDS_FLAGS_FUSION`, no TMZ (`amdgpu_gmc_tmz_set` leaves
         10.3.6 off);
       - no MALL;
       - VRAM type and width from `atom_integrated_system_info`
         (`amdgpu_atomfirmware_get_vram_info`'s APU arm);
       - firmware versions from the graphics set, SOS 0 (13.0.5 loads only
         the TOC).
       The coordinator publishes topology, chip and PCI revision. ACCEL
       stays off.
    3. ~~Submission~~ (done). A small owner seam (`amdgpu_rdna2_client`) lets the RDNA2
       submitter lock Navi22's cold boot or Raphael's coordinator. After
       graphics boots, Raphael registers the submitter, GFXHUB client VMIDs
       1–7 and a visible client heap from the carve-out (an APU has no
       hidden VRAM). ACCEL_WORKING and `available_rings` (one SDMA) follow
       from that. Also needed:
       - live READ_MMR_REG through the coordinator: nv.c's list, with no
         GFXOFF reference, since GFXOFF stays disallowed;
       - DRM version 3.64;
       - the client frames drop the HDP read-cache invalidate.
       All of it is unproven on silicon: the tests cover the layouts,
       frames and INFO replies, not a Mesa context.
    4. ~~Media rings~~ (done): VCN decode/encode and JPEG for clients.
       - The media frames' VM flush follows the hub's registers
         (`submit::MediaHub`, as `adev->vmhub` holds them). Before, it
         hard-coded MMHUB 2.0's offsets: CONTEXT0 PTB 0x72b, ENG0
         SEM/REQ/ACK 0x6d1/0x6e3/0x6f5, engine stride 1. `mmhub_v2_3`
         moved them (0x940, 0xa00/0xa01/0xa02) onto base index 1, with
         engine and context strides of 8. A vcn-raphael test pins both
         hubs' absolute registers.
       - `vcn::Client` takes Raphael's MMHUB 2.3/2.4 and OSSSYS 5.2.1
         (`navi10_ih` keeps osssys_5_0_0's IH VMID LUT).
       - Power: `PowerUpVcn` / `PowerDownVcn` through SMU 13.0.5 for the
         idle work and `begin_use` (always sent: no MM_DPM_PG to consult).
         The DPG register lists go through the display loader's PSP
         session. JPEG stays powered across a VCN idle gate, as on Navi22.
       - The VCN client submit and the idle task take the
         `amdgpu_rdna2_client` guard. Its media view carries Raphael's
         coordinator with that PSP session, and returns Navi22's
         cold-boot errors so the callers read the same.
       - `register_raphael` publishes the rings and starts the idle work.
    5. Hangs: what exists, no code yet. A CP privileged or bad-opcode
       fault fails its job through `route_fences`, as on Navi22. Nothing
       recovers the rings: Navi22's watchdog and recovery are not
       registered for Raphael, and APU mode-2 reset is not ported. A hung
       ring makes later admissions fail with EBUSY at the 10 s throttle
       deadline. Suspend stays refused while graphics is up
       (`Loader::stop`).

## Ring recovery

Linux's `amdgpu_job_timedout` climbs a ladder for a timed-out GC 10.3 job,
each rung tried only if the one before failed:
1. Soft recovery (`amdgpu_ring_soft_recovery`): `gfx_v10_0_ring_soft_recovery`
   writes `SQ_CMD` (kill, broadcast, `CHECK_VMID`) for the job's VMID under
   RLC safe mode, repeating for up to 10 ms until the fence signals. The
   fence carries -ENODATA.
2. Per-queue reset (`amdgpu_ring_reset`):
   - `gfx_v10_0_reset_kcq`: KIQ UNMAP_QUEUES with RESET_QUEUES, the HQD
     going inactive, MQD re-init, MAP_QUEUES, a ring test;
   - `gfx_v10_0_reset_kgq`: `CP_VMID_RESET` through the KIQ, then the same
     re-init.
   SDMA 5.2's queue reset (`sdma_v5_2_reset_queue`) goes through
   `amdgpu_dpm_reset_sdma`, which SMU 13.0.5 does not implement, so an
   SDMA hang falls through.
3. The full reset: mode 2 for MP1 13.0.5 (`nv_asic_reset_method`):
   `GfxDeviceDriverReset(SMU_RESET_MODE_2)`, then every IP re-initialized,
   firmware and display included.

NARF's Navi22 has detection (`amdgpu_navi22_tdr`) and the full reset (a
rebuilt owner after mode 1). Its job ledger treats any hang as terminal,
since the submitter is replaced. Raphael's port:

11. Ring recovery:
    1. ~~Detection~~ (done). The watchdog (`amdgpu_navi22_tdr`) samples
       Raphael's queues through the client seam and prints Linux's "ring
       timeout" line. It starts when the submitter registers.
    2. ~~Per-job guilt~~ (done). `Jobs::recovered` fails the timed-out job
       alone: `TimedOut`, its context guilty, the error kept after it
       retires. The ledger records each job's VMID for the next rung.
    3. ~~Soft recovery~~ (done), GFX and compute. `GfxEngine::kill_waves`
       writes `SQ_CMD` (kill, broadcast, `CHECK_VMID`) inside RLC safe
       mode, entered only with the RLC running. The coordinator repeats it
       for up to 10 ms until the job's fence signals. A kernel job (VMID 0),
       an SDMA hang, or a fence that stays put is terminal, as before: every
       job fails and the submitter stops.
    4. Per-queue reset.
       - ~~Compute~~ (done): `kiq::Engine::reset_compute`, after
         `gfx_v10_0_reset_kcq`. KIQ UNMAP_QUEUES (RESET_QUEUES) and its ring
         test; the HQD inactive under GRBM select in RLC safe mode; the MQD
         restored from the map-time backup (unmapping saves live HQD state
         into it), the ring NOP-filled, both pointers zeroed; MAP_QUEUES, then
         the KIQ and compute ring tests.
       - Jobs: `Jobs::reset` fails the timed-out job (`TimedOut`, context
         guilty) and cancels the ones behind it on that ring, with their
         contexts left usable; Linux re-emits those, this does not. The
         errors are recorded before `force_complete` writes the ring's last
         sequence into both fence writebacks, so no sample can retire the
         guilty job as done. The queue's memory is released then: the
         unmap proved it can no longer fetch that work.
       - ~~GFX ring 0~~ (done), after `gfx_v10_0_reset_kgq`, split between
         the two owners:
         - the KIQ writes `CP_VMID_RESET` for the job's VMID and pipe 0's
           queue, waits for the MQD's `cp_gfx_hqd_active` (dword 130) to
           read 0 and the register to clear, then ring-tests;
         - the GFX owner restores ring 0's MQD from its map-time backup and
           empties the ring;
         - the KIQ remaps it (ENGINE_SEL 4), and the GFX owner ring-tests it.
         A kernel job (VMID 0) is not reset. Ring 1 carries no client work
         and is left alone.
    5. ~~Mode 2~~ (done), for SDMA hangs, kernel-job hangs and failed
       queue resets: `amdgpu_platform::recover`, after
       `amdgpu_device_gpu_recover`. Linux recovers APUs by default
       (`amdgpu_gpu_recovery` -1); `amdgpu.gpu_recovery=0` turns it off, and
       Navi22's per-boot budget applies.
       1. Quiesce: the client path withdrawn (every job fails), the watchdog
          stopped, the IH ring disabled, every fence wait abandoned, the
          stream disabled.
       2. `psp_suspend`: DMUB stopped, the TMR released, the PSP ring stopped
          (`Loader::stop_for_reset`; a plain stop still refuses with
          graphics up).
       3. `nv_asic_mode2_reset` (`amdgpu_raphael_reset`):
          - the engine-hung scratch bit set;
          - bus mastering off, with the command register and BARs cached;
          - PMFW `GfxDeviceDriverReset(MODE2_RESET)` (message 10, argument 2);
          - the cached state restored;
          - MEMSIZE alive;
          - the scratch bit cleared.
       4. Re-initialization:
          - the PSP session booted again, which reloads the graphics set and
            runs the RLC autoload;
          - DMUB notifications;
          - the graphics coordinator re-armed and run again, then media,
            then client registration (step 13);
          - the recovery counter (`amdgpu_ctx::recoveries`) moves, so older
            contexts see the reset.
       5. The stream put back on its validated mode, as `resume` does. The
          scanout is not cleared: `amdgpu_device_check_vram_lost` reports no
          loss for mode 2.
       Unproven on silicon. In particular, what mode 2 resets on 13.0.5
       (whether the PSP and DCN come back on their own) follows Linux's
       order rather than a measurement.

## Suspend and resume

12. ~~S3 with graphics up~~ (done). Before this, the display's suspend
    refused with graphics loaded: `Loader::stop` will not release the TMR
    while the RLC and CP run from it. Linux's `amdgpu_device_suspend` and
    `amdgpu_device_resume` take every IP down and back up, and for an APU
    the carve-out stays in place (`amdgpu_device_evict_resources` skips
    VRAM eviction unless going to S4). The work is split across the
    system-PM phases (`GraphicsPm`):
    1. Async prepare, with the executor and interrupts live:
       - the rings drained (`amdgpu_fence_driver_hw_fini`, up to 10 s),
         the media rings included (step 14);
       - the client path withdrawn;
       - VCN stopped and its VCPU buffer saved (step 14);
       - the IH ring disabled;
       - every fence wait abandoned.
    2. Sync suspend: the stream disabled, then, with graphics quiesced,
       `psp_suspend` (TMR and ring released). S3 powers the engines off,
       which is the reset that release needs.
    3. Sync resume: unchanged. The PSP session boots again (reloading the
       graphics set and running the RLC autoload), and the stream is
       replayed.
    4. Async resume: the coordinator re-armed and run again (step 13),
       then media and clients, via the rebuild helper shared with mode 2
       recovery. A suspend that aborted before the PSP stopped never
       powered the GPU off, so that resume runs the mode 2 reset first.
    Contexts survive: no recovery count, and the rings were drained. VCN
    sessions survive too (step 14).

## Owner re-init

13. ~~In-place owner re-init~~ (done). Recovery and resume used to retire
    the spent coordinator, quarantined, and build a new one, leaking its
    carve-out reservations every cycle. Linux's hw_init after a reset runs
    again over the BOs it already holds; `ColdBoot::rearm` does the same.
    Every owner returns to Prepared on its own reservations, and `run` and
    `run_media` bring the same buffers up again:
    - GFX, KIQ/compute and both SDMA queues: write pointers and sequences
      back to 0 (an old sequence against a reset writeback would read as a
      hang), proofs cleared, the golden settings and MQD backups taken
      again. Each bring-up step clears its own ring memory.
    - The SDMA proof ring: proven again.
    - GMC: both hubs programmed again on the same boot aperture, and the
      GART re-enabled on the same table (zeroed, boot pages mapped again).
      A new owner token makes VMIDs lent before useless; registration lends
      them again. Refused, unchanged, while a VM holds a context or a GTT
      binding holds GART pages, since the zeroed table would drop their
      entries (no Raphael path binds either today).
    - IH: the ring reprogrammed in place on its MSI-X entry (or MSI
      address), written again, and its vector re-enabled. Subscriptions
      from before end `Revoked`; slot generations are never reused, so a
      late drop of one cannot take a new subscriber's slot.
    - VCN and JPEG: started again on the same instance, JPEG and client
      buffers; the idle runtime is fresh.
    - A fresh SMU mailbox; versions, apertures, proof and topology are
      read again.
    The client VRAM heap is reserved once and kept across cycles. A
    coordinator whose re-arm is refused is retired and a new one built, as
    before. The rebuild logs whether it re-armed, how many owners are
    retired and how much of the carve-out is free.

## VCN sessions across S3

14. ~~VCN sessions across S3~~ (done). Before this, the resume's media start
    zeroed the VCPU buffer (stack, context, fw_shared), so every decode and
    encode session the firmware held was gone, and the client path's
    session table was dropped with it. Linux's `vcn_v3_0_suspend` runs
    `vcn_v3_0_hw_fini` and then `amdgpu_vcn_suspend`, which copies the VCPU
    BO to system memory. `vcn_v3_0_resume` copies it back
    (`amdgpu_vcn_resume`) before `vcn_v3_0_hw_init`. Here:
    1. The prepare's drain waits on the VCN and JPEG rings too, as
       `amdgpu_fence_driver_hw_fini` does on every ring.
    2. The client path is withdrawn with its decode-session table kept
       (`amdgpu_navi22_cs::suspend`).
    3. `ColdBoot::suspend_media` stops a running VCN and JPEG (an owner the
       idle work gated is already stopped), then copies each instance's VCPU
       BO, all 644 KiB, to the heap in 64 KiB steps between yields.
    4. At resume, the re-armed media start writes the saved copy back in
       place of zeroing the BO and setting fw_shared's flags. The image
       carries those flags. The rings and buffers after the BO are zeroed
       as before, and `vcn_v3_0_start` resets the queue pointers in
       fw_shared.
    5. Registration keeps the session table only when every instance's
       BO came back. Otherwise it starts empty, as the firmware does.
    A failed save is logged, and that resume starts media with no
    sessions. A mode 2 recovery drops any saved copy: the contexts are told
    of the reset. Linux saves and restores there too (its full-reset path
    suspends every IP first), but this recovery does not stop a VCN that
    may be hung. On an APU the carve-out survives S3 itself; the copy
    matters because a start zeroes the BO, and it keeps the suspend
    independent of that.

## GFX power gating and GFXOFF

15. ~~GFXOFF~~ (done, `amdgpu_raphael_gfxoff`). Before this, GFX stayed
    powered: the SMU stage disallows GFXOFF and nothing allowed it again.
    Linux's late init gates every IP. On GC 10.3.6,
    `gfx_v10_0_set_powergating_state(GATE)` runs `gfx_v10_cntl_pg(true)`
    and then `amdgpu_gfx_off_ctrl(true)`; UNGATE runs the disable request
    first, then `gfx_v10_cntl_pg(false)`. Here:
    1. `gfx_v10_cntl_pg` (`Gfx::set_power_gating`): in RLC safe mode,
       `RLC_PG_CNTL.GFX_POWER_GATING_ENABLE` set or cleared. On enable,
       `RLC_PG_DELAY_3` gets the APU group's CGPG hysteresis (`0x4E20`,
       200 us), since Raphael has `AMD_PG_SUPPORT_GFX_PG`.
    2. The request count is Linux's `amdgpu_gfx_off_ctrl`, through Navi22's
       controller. It starts at 1, GATE takes it to 0, and PMFW's
       `AllowGfxOff` (message 22) follows 100 ms later
       (`GFX_OFF_DELAY_ENABLE`). A disable request before then cancels it;
       one while GFXOFF is in effect sends `DisallowGfxOff` (23) first.
    3. GATE runs once clients are served, after the first boot and after
       every rebuild. UNGATE runs before S3 (after the drain and the client
       withdrawal) and before a mode 2 reset, as `amdgpu_device_ip_suspend`
       does.
    4. Driver reads of GC registers hold a disable request:
       - READ_MMR_REG, as `amdgpu_info_ioctl` does;
       - the hang snapshot, as `gfx_v10_ip_dump` does.
       Submission writes only memory and the doorbell, which wakes GFX
       itself; progress sampling reads memory and NBIO. Soft recovery and
       the queue resets act on a busy, so powered, engine. None of these
       take anything, as in Linux. JPEG reads `GB_ADDR_CONFIG` only at
       start, before GATE, and the VCN wake uses the cached value.
    5. Each coordinator lifetime has its own count under the display
       owner's lock. A re-armed coordinator starts at 1 again, and a delayed
       allow from before carries an epoch no later lifetime has.
       (Navi22's controller is one global, which cannot restart once
       stopped.)
    6. `amdgpu.ppfeaturemask` is Linux's knob. Its default (`0xfff7bfff`)
       has `PP_GFXOFF_MASK`. A mask without it keeps every GFXOFF request
       inert, while power gating still follows GATE and UNGATE, as in Linux.
    Clock gating, which CGPG's hysteresis counts from, is step 16.

## Clock gating

16. ~~Clock gating~~ (done, `Gating::new_raphael`). Linux's late init runs
    `amdgpu_device_set_cg_state(GATE)` over every IP before
    `set_pg_state(GATE)`, and `amdgpu_device_ip_suspend_phase1` ungates
    power before clocks. `nv_common_early_init` gives GC 10.3.6 its own
    set: GFX MGCG, MGLS, CGCG, CGLS, 3D CGCG/CGLS, RLC and CP light sleep,
    FGCG; MC MGCG/LS; SDMA LS; HDP MGCG/LS; ATHUB MGCG/LS; IH; VCN and JPEG
    MGCG. Raphael is a resolution of the discrete RDNA2 gating engine:
    - nv_common: nothing. `nv_common_set_clockgating_state` acts only on
      NBIO 2.3.x and 3.3.x, and Raphael's is 7.2, so Linux never reaches
      its HDP or SMUIO gating.
    - GMC: `mmhub_v2_3` on MMHUB 2.3.0/2.4.x, all on bank 1. Medium grain
      is the `MM_ATC_L2_CGTT_CLK_CTRL` soft override and DAGB0's six CG
      disables; light sleep is the ATC L2 MGLS override and DAGB0's write
      and read LS overrides. Then ATHUB by version: `athub_v2_1` (2.1.0-2.1.2,
      2.4.0) at 0x0009, `athub_v2_0` (1.3.1, 2.0.0, 2.0.2) at 0x000a with bits
      18/19, any other version untouched. Raphael's ATHUB revision is
      unconfirmed. ATHUB_MGCG/LS are informational: both files test MC_MGCG,
      MC_LS and HDP_LS.
    - IH: `navi10_ih`, Navi22's register on every `navi10_ih` OSSSYS.
    - GFX: `gfx_v10_0_update_gfx_clock_gating` in RLC safe mode, the
      sequences Navi22 runs. Raphael also sets MGLS (RLC and CP memory
      light sleep), 3D CGLS and FGCG, which those sequences already follow
      Linux for.
    - SDMA: `sdma_v5_2` over its one instance. With no SDMA_MGCG the
      clocks stay forced on, and SDMA_LS sets the memory power override.
    - VCN and JPEG: the media owner programs their gating in its start and
      stop (`vcn_v3_0_clock_gating_dpg_mode`, `vcn_v3_0_enable_clock_gating`,
      JPEG's pair). Linux's late-init `vcn_v3_0_set_clockgating_state(GATE)`
      is not repeated here.
    `amdgpu.cg_mask` (Linux's knob) masks the flags. Clock gating runs with
    GFX powered: at GATE before GFXOFF is allowed, at UNGATE after it is
    disallowed. A re-arm returns the owner to Idle, since the reset left
    every gating register at its default.

## Open

- Raphael's exact NBIO, MMHUB and OSSSYS revisions come from a discovery table
  nothing here has read; NBIO is inferred to be `nbio_v7_2`'s from Linux's
  history (step 4).
- PMFW's initial GFXOFF state on 13.0.5: Linux starts with a GFXOFF request
  count of 1 (disallowed) and never sends `DisallowGfxOff` at init. This
  port sends it at the SMU stage, before any GC access, and allows GFXOFF
  only at GATE (step 15).
