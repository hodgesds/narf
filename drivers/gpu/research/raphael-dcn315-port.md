# Raphael (GC 10.3.6 / DCN 3.1.5) port map

Raphael is the desktop Zen4 iGPU, `1002:164E`: Ryzen 7000 desktop, Ryzen
7045HX (Dragon Range) and Ryzen 9000 (Granite Ridge) all carry it. It is
RDNA2, not RDNA3; the Ryzen 7040 *mobile* parts are Phoenix (GC 11.0.1 /
DCN 3.1.4), which already has a native display path.

Source: Linux `v7.3-rc4` in `/usr/src/linux`. Every claim below cites the file
it came from.

## IP set (`amdgpu_discovery.c`)

| IP | Version | Linux block | Firmware (`MODULE_FIRMWARE`) |
|---|---|---|---|
| GC | 10.3.6 | `gfx_v10_0` | `gc_10_3_6_{ce,pfp,me,mec,mec2,rlc}.bin` |
| DCN | 3.1.5 | `dcn315_resource.c` | `dcn_3_1_5_dmcub.bin` (`FIRMWARE_DCN_315_DMUB`) |
| PSP (MP0) | 13.0.5 | `psp_v13_0` (TOC + TA, as 13.0.4) | `psp_13_0_5_{toc,ta}.bin` |
| SMU (MP1) | 13.0.5 | `smu_v13_0_5_ppt.c` | none (APU, PMFW BIOS-resident) |
| SDMA | 5.2.6 | `sdma_v5_2` | `sdma_5_2_6.bin` |
| VCN | 3.1.2 | `vcn_v3_0` | `vcn_3_1_2.bin` |

`AMDGPU_FAMILY_GC_10_3_6`; APU by the GC list. The firmware table is
`amdgpu::RAPHAEL_FW`, in `enum AMDGPU_UCODE_ID` order, and is pinned by
`smoke_amdgpu_raphael_identity_matches_linux`. The chip is still routed to
`UNAUDITED_FW` until a PSP 13.0.5 load path exists.

## DCN 3.1.5 against the DCN 3.1.4 code

`dcn315_resource.c` is DCN31 proper. `dcn314_resource.c` forks several blocks.

| Block | DCN 3.1.4 | DCN 3.1.5 | State in NARF |
|---|---|---|---|
| HUBP | hubp31 | hubp31 | admitted (offsets identical) |
| DPP | dpp3 / dcn31 | dpp3 / dcn31 | admitted (offsets identical) |
| MPC | mpc31 | mpc31 | admitted (offsets identical) |
| OPP | opp31 | opp31 | admitted (offsets identical) |
| Connector inventory | DIG BE at 0x20b2 | DIG BE at 0x20b1 | admitted on the DCN30 arm |
| HUBBUB | hubbub31 | hubbub31 | DET/COMPBUF/CRC registers +0x11 — audit before use |
| OTG | **optc314** | optc31 | ported (`layout_shift`, optc31 disable) |
| DCCG | **dccg314** | dccg31 | refused (`Dccg::new`) |
| DIO stream encoder | **dcn314** | dcn30 | ported (enc2 unblank with DIG_START) |
| DIO link encoder | dcn31 | dcn31 | ported (`DIG_WINDOWS`: DIG_BE_CNTL/EN_CNTL −1); PHY commands still need DMUB |
| Clock manager | dcn314 + SMU 13.0.4 | dcn315 + SMU 13.0.5 | refused (SMU version list) |
| DMUB | DCN314 | DCN31 functions | refused (`amdgpu_dmub` version list) |
| DML | dml314 | dml31 + dcn315 SoC BB (`dcn31_fpu.c`) | not started |
| Boot handoff window | `DCN_3_1_4` | — | not present; HUBP/OTG_CONTROL offsets match |

Resource caps are identical (`res_cap_dcn315`): 4 timing generators, 4 OPPs,
5 stream encoders, 5 DIG link encoders, 5 PLLs, 5 DDC, 16 VMIDs. Plane power
gating is on (no `disable_*_power_gate` in `debug_defaults_drv`); Z10 is
off ("hw not support it").

### Register differences the existing constants hit

These came from a mechanical audit. Every annotated (`// linux: mm…`) and every
name-and-value-matched constant in the DCN314 modules was checked against
`dcn_3_1_5_offset.h` / `_sh_mask.h`:

- `amdgpu_dcn_otg.rs`: `OTG_CLOCK_CONTROL` 0x1b85→0x1b86, `OTG_VSTARTUP_PARAM`
  0x1b86→0x1b87, `OTG_VUPDATE_PARAM` 0x1b87→0x1b88, `OTG_VREADY_PARAM`
  0x1b88→0x1b89. This is the same +1 that `otg()` already applies for DCN30.
- `amdgpu_dcn_otg_drr.rs`: `OTG_STATIC_SCREEN_CONTROL` 0x1b81→0x1b82;
  `OTG_DRR_CONTROL` 0x1b9a→0x1b9b; `OTG_GLOBAL_CONTROL0` 0x1b8f→0x1b90.
- `amdgpu_dcn.rs`: `OTG0_OTG_INTERRUPT_CONTROL` does not exist on DCN 3.1.5.
- `amdgpu_dcn_dccg.rs`: `DTBCLK_P_CNTL`, `OTG_PIXEL_RATE_DIV` do not exist.
- `amdgpu_dio.rs`, `amdgpu_dcn_inventory.rs`: `DIG_BE_CNTL` 0x20b1→0x20b0,
  `DIG_BE_EN_CNTL` 0x20b2→0x20b1.
- `amdgpu_dcn_stream.rs`: DCN 3.1.5 has `DIG_FE_CNTL.DIG_START` (shift 10);
  DCN 3.1.4 does not.

In total, 720 register names shared by both headers sit at different offsets,
concentrated in DIG (225), OTG (200), DC perfmon (190), VPG (70) and DCHUBBUB
(18). DCN 3.1.5 drops 45 DSCC, 38 AZ and 30 DP registers.

### Clock manager — a different SMU protocol, not a renumbering

`dcn315_smu.c` against `dcn314_smu.c`:

- Response register `MP1_SMN_C2PMSG_38` (DCN314: `_91`). Parameter register
  `MP1_SMN_C2PMSG_37` (DCN314: `_83`).
- The message id goes through an **indirect** SMN write, not a direct MMIO
  write: `mmMP1_C2PMSG_3` = 0x3B1050C via `BIF_BX_PF2_RSMU_INDEX/DATA`, with a
  read-back.
- Message ids are renumbered: `SetDtbClk` is 0x0A (DCN314: 0x17) and
  `GetDtbclkFreq` is 0x09. `Spare0`/`Spare1` sit at 0x03/0x05, and
  `Message_Count` is 0x14.
- `DpmClocks_t`: four levels per clock (as DCN314). `DfPstateTable_t` is 12
  bytes, without DCN314's `WckRatio` and `Spare[3]`, so the table must be
  parsed with its own layout.

## Order of work

1. ~~Identity: Family, firmware names, VCN line~~ (done).
2. ~~`Profile::Dcn315` with shared-block admission and refusal of the rest~~ (done).
3. ~~OTG: optc31 layout and disable~~ (done). DCN 3.1.5 inserts
   `OTG_CRC_CNTL2` at 0x1b69 and drops `OTG_INTERRUPT_CONTROL` (0x1b59); every
   DCN 3.1.4 OTG register at or above 0x1b69 is +1. `optc31_enable_crtc` is
   identical to optc314's, as is ODM bypass. `optc31_disable_crtc` parks the
   segments, clears `OPTC_MEM_SEL` and then the OPTC underflow. DRR stays
   DCN30-only, though DCN 3.1.5's `OTG_STATIC_SCREEN_CONTROL` (0x1b82) is
   DCN30's offset.

   Open question for the Phoenix path: NARF's DCN 3.1.4 `disable()` also
   parks segments and clears `OPTC_MEM_SEL`, which is optc31's sequence;
   Linux's `optc314_disable_crtc` does neither. It was left unchanged here.
4. ~~DIO link encoder: DIG BE −1, behind a DCN315 version entry~~ (done).
   Every DP0 register and mask the module uses is identical in the 3.1.5
   headers. Both DCNs set `dmub_command_table`, so PHY control goes through
   DMUB's VBIOS transmitter command on both; nothing reaches it on Raphael
   until step 9.
5. ~~Stream encoder~~ (done). `dcn30_str_enc_funcs`: `enc2` unblank pulses
   `DIG_FE_CNTL.DIG_START` (0x208b, mask 0x400) before the steering-FIFO
   reset; there is no `DP_PIXEL_PER_CYCLE_PROCESSING_MODE` field.

   Two open questions on the shared DCN 3.1.4 path, found while diffing and
   not changed here:
   - ~~DCN 3.1.4 never enabled the DIG FIFO~~ (fixed).
     `enc314_stream_encoder_dp_unblank` ends with `enc314_enable_fifo`
     (`DIG_FIFO_CTRL0`: READ_START_LEVEL 7, reset pulse, `DIG_FIFO_ENABLE`),
     which the code describes as "now needs to be explicitly enabled ... per HW docs".
     NARF's unblank now does the same; `program` sets one pixel per container
     (`enc314_set_dig_input_mode`), and teardown disables the FIFO after the
     link (`reset_dio_stream_encoder`). Linux's earlier `enable_fifo` in
     `setup_dio_stream_encoder` is not repeated, because unblank resets and
     re-enables the FIFO anyway.
   - ~~DP blank skipped the vblank defer and steering reset~~ (fixed).
     `enc1_stream_encoder_dp_blank` (every DCN this module serves) leaves a
     disabled stream alone. Otherwise it sets `DP_VID_STREAM_DIS_DEFER = 2`,
     drops the enable, waits up to 100.2 ms for `DP_VID_STREAM_STATUS` to clear,
     then sets `DP_STEER_FIFO_RESET`. NARF now does the same, except that a
     timeout is an error and the steering reset is then withheld.
6. DCCG: `dccg31.c` pixel-rate and DTBCLK paths.
7. Clock manager: `dcn315_smu.c` mailbox (indirect message write) and
   `dcn315_clk_mgr.c` DPM table parse.
8. DML: dml31 with the dcn315 SoC bounding box; HUBBUB DET/COMPBUF offsets.
9. DMUB `dcn_3_1_5_dmcub.bin` with PSP 13.0.5, then the boot-handoff window,
   then the Late worker arm.

No step has run on Raphael silicon.
