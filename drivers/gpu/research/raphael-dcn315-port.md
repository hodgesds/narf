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
| DCCG | **dccg314** | dccg31 | ported (DPP DTOs; dccg314-only operations refused) |
| DIO stream encoder | **dcn314** | dcn30 | ported (enc2 unblank with DIG_START) |
| DIO link encoder | dcn31 | dcn31 | ported (`DIG_WINDOWS`: DIG_BE_CNTL/EN_CNTL −1); PHY commands still need DMUB |
| Clock manager | dcn314 + SMU 13.0.4 | dcn315 + SMU 13.0.5 | ported (`Mailbox::Dcn315`) |
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
6. ~~DCCG~~ (done). Every shared DCCG register keeps its DCN 3.1.4 offset;
   `dccg31_update_dpp_dto` is dccg2's plus a root-gating early return.
   `dccg31_funcs` lacks `set_pixel_rate_div`, `set_dtbclk_p_src` and
   `trigger_dio_fifo_resync`, so the display skips the K1/K2 dividers as Linux
   does. dcn315 has no USB4 DPIA (dcn314: `usb4_dpia_count = 4`).

   The DP DTO was missing on both DCNs and is now programmed.
   `dcn31_program_pix_clk`, which both build, clocks a DP 8b/10b stream from
   the OTG's DP DTO (`OTGn_PIXEL_RATE_CNTL`, `DP_DTOn_PHASE/MODULO`, stride
   4, unchanged in the 3.1.5 header): phase = pixel clock, modulo =
   DPREFCLK, or the video-optimized /1.001 ratio; then `DP_DTO0_ENABLE` and
   `PIPE0_DTO_SRC_SEL = 1` (2 bits on 3.1.4, 1 bit on 3.1.5). NARF never
   set it, so a pipe the GOP left idle had no programmed pixel clock. The
   reference comes from `ClockManager::dprefclk_khz`: 600 MHz on DCN 3.1.4,
   and from SMU `GetDprefclkFreq` on DCN 3.1.5 once step 7 lands.

   On DCN 3.1.4, while the SPLL spreads (`CLK6_0_CLK6_spll_field_8.spll_ssc_en`),
   `dcn314_init_clocks` lowers that reference by half the spread
   (`dce_adjust_dp_ref_freq_for_ss`). The spread is the VBIOS DP entry
   (`dce_clock_read_ss_info`; GPU_PLL is unsupported on atomfirmware, so
   the DISPLAY_PORT entry is used: dce_info 4.1 own fields, 4.2–4.4
   `smu_info`, 4.5 integrated info 2.2/2.3). `dcn314_read_ss_info_from_lut`
   then replaces it, even with zero, whenever `CLK2_BYPASS_SEL` < 5
   (`ss_info_table` = {0, 0, 375, 375, 375} thousandths of a percent).
   NARF reproduces this, including Linux's 31.32 fixed-point rounding:
   0.375 % on 600 MHz is 598 874 kHz, not 598 875. DCN 3.1.5's clock
   manager makes no such adjustment.
7. ~~Clock manager~~ (done). Chosen when discovery reports MP1 13.0.5
   *and* DCN 3.1.5, and refused unless discovery's MP1 segment 0 is the
   0x16000 Linux hard-codes. The parameter and response are C2PMSG_37/38.
   The id is written to SMN `0x3B1050C` (`MP1_C2PMSG_3`) through NBIO
   `PCIE_INDEX2/DATA2` (0xe/0xf at base 0 in nbio 7.2 and 7.7), read back
   and retried up to five times; a rejection does not reset RESPONSE. Start
   asks `GetDprefclkFreq` (0x13) for the DP DTO's reference. The table is the
   176-byte `DpmClocks_315_t` (WCK ratio 1). `SetDtbClk` is 0x0A. Both
   mailboxes now clamp what is asked of PMFW for DISPCLK to
   `min_disp_clk_khz` (100 MHz), as Linux does on both.

   Not ported, and the reasons:
   - `dcn315_update_clocks` locks p-state with `UNSUPPORTED_DCFCLK` when
     the mode cannot support a p-state change. NARF's DML makes no
     p-state-support decision yet, so every plan is treated as supporting
     one; step 8 has to supply that bit.
   - `dcn315_disable_otg_wa` / `dcn314_disable_otg_wa` stop OTGs of streams
     that are DPMS-off or have no plane around a DISPCLK change. NARF owns
     no such streams; neither DCN does it.
   - The watermark table transfer (`TABLE_WATERMARKS`, Dram2Smu) is not
     sent on either DCN.
8. ~~DML parameters and dml31 differences~~ (done). For one plane on one pipe,
   dml31 and dml314 share the prefetch schedule, swath/DET configuration and
   watermark formulas; they differ in `dcn3_15_ip`/`_soc` (192 KB default
   DET, 0.38 % downspread, 9 tile repeaters, Z8 50/50 µs), the
   `dcn315_clk_mgr.c` WM_A row (129/11.5/14.5 µs for DDR5 and LPDDR5), the
   maximum VStartup (dml31: whole vblank − 1; dml314: also bounded by
   `VBlankNomDefaultUS`) and `MIN_DST_Y_NEXT_START` (rq_dlg_calc_31
   programs the vblank start).

   ~~The vactive p-state decision~~ (done). `DRAMClockChangeSupport` for one
   plane is the line-buffer hiding time (≤ 12 lines) plus the full-DET
   buffering time, less the scaler delay, the urgent and the DRAM-change
   watermarks. Under unbounded requesting the DET includes the whole
   compressed buffer. A margin > 0 is vactive; with one timing generator,
   anything else is vblank. `dcn31_calculate_wm_and_dlg_fp` allows p-state
   only in vactive, on both DCNs. On DCN 3.1.5 a non-vactive mode is then
   recomputed with `dummy_pstate_latency_us` (10 µs), and the clock manager
   locks p-state by asking for `UNSUPPORTED_DCFCLK` (10 GHz). DCN 3.1.4's
   clock manager ignores the flag, as Linux's does. LINUX-GAP: Linux chooses
   the latency from the *previous* validation, so such a mode alternates
   between 129 µs and 10 µs across commits; NARF takes the
   dummy-with-lock pairing deterministically.

   ~~DCHUBBUB DET split, compressed buffer, unbounded requesting and arbiter
   watermarks~~ (done, both DCNs, `amdgpu_dcn_hubbub`). Neither path
   programmed any of them before, so the firmware's split and watermarks
   were inherited. hubbub31 serves both; the arbiter registers share offsets,
   and the DET/COMPBUF block is +0x11 on DCN 3.1.5.
   - The split follows `populate_dml_pipes_from_context`. A lone pipe with
     a surface ≤ 5120 wide (on DCN 3.1.5 also below DPM DISPCLK / 1.0038)
     gets 192 KB with unbounded requesting. Beside live pipes it gets 384 KB
     (DCN 3.1.4) or an even share of 896 KB capped at 384 (DCN 3.1.5). A
     pipe the boot firmware left live keeps its DET; a split that does not
     fit beside it is refused. The mode math uses the DET actually given.
   - The sequence is Linux's: raise the watermarks and shrink the compressed
     buffer (to 64 KB on DCN 3.1.5) before the change, then the DET and
     `hubp31_set_unbounded_requesting`, then grow the compressed buffer once
     every DET has applied. Teardown returns the DET to 0.
   - Watermarks are written to all four sets as `ns × refclk_MHz / 1000`
     cycles; a value its field cannot hold is refused, not clamped.
     `FRAC_URG_BW_NOM` is max(read, prefetch pixel) bandwidth over return
     bandwidth. Linux lowers watermarks to values computed for the whole
     state; this plane model does not see a pipe the GOP left live, so the
     exact values (and allowing self-refresh) are written only when this
     pipe is the hub's sole user, and otherwise only raised above what the
     hardware holds.
   - DCN 3.1.4's 2100 µs minimum Z8 residency applies unconditionally (no
     stutter period is computed).

   The vactive decision above runs on the DET and compressed-buffer sizes
   this plan supplies.
9. DMUB `dcn_3_1_5_dmcub.bin` with PSP 13.0.5, then the boot-handoff window,
   then the Late worker arm.

No step has run on Raphael silicon.
