# Navi22 HDMI bring-up audit — 2026-10-26

Reference: local Linux checkout `/home/daniel/git/linux`, commit
`ecd997b0189a`. Linux paths below are relative to
`drivers/gpu/drm/amd/display/dc/`. The target is the RX 6750 XT / DCN3.0
DIO HDMI path, progressive RGB, one display. This is a source comparison
of the selected callbacks, supplemented by Rust register models. It does
not prove that the physical PHY or sink has locked.

NARF's boot path is `fb::amdgpu_boot::navi22_native_display` →
`amdgpu_navi22_platform::modeset_displays` → `light` →
`ColdBoot::modeset_display` → the single-stream `Pipeline`. It draws color
bars before Xorg starts; a missing boot pattern cannot be attributed only
to llvmpipe or the greeter. Multi-stream commits have separate orchestration
in `amdgpu_navi22_multi.rs` and share the block owners.

## Selected callbacks and comparison

| Checkpoint | Linux implementation | NARF result |
| --- | --- | --- |
| Actual callback selection | `hwss/dcn30/dcn30_init.c`, `dccg/dcn30/dcn30_dccg.c`, `dio/dcn30/dcn30_dio_{link,stream}_encoder.c` | DCN3.0 inherits DCN2 timing/stream control and DCE112 TMDS pixel clocks. The DCCG table has no `enable_symclk_se` or `set_pixel_rate_div`; the stream table has no `enable_fifo`, `enable_stream`, or `map_stream_to_link`. Those newer hooks are not missing DCN3.0 steps. |
| Display takeover | `hwss/dcn30/dcn30_hwseq.c::dcn30_init_hw`; `hwss/dcn10/dcn10_hwseq.c::dcn10_init_pipes` | `Pipeline::init_hw` and `amdgpu_dcn30_takeover` initialize DCCG, golden tables when required, VGA, inherited pipes, MPCCs, power gates, and timing double buffering. Existing takeover models cover active GOP streams and quarantine on failure. |
| Clock and bandwidth admission | `dcn30_prepare_bandwidth` → `dcn20_prepare_bandwidth`; `clk_mgr/dcn30/dcn30_clk_mgr.c` | Board-derived DPM/DML admission, clocks before watermarks, bounded acknowledgements. Earlier HPET calibration and physical fabric geometry fixes are retained. |
| OPTC clocks | `optc/dcn10/dcn10_optc.c::optc1_enable_optc_clock` | Input clock then OTG clock, with acknowledgements, before programming the pixel clock. |
| TMDS pixel clock | `dce/dce_clock_source.c::dcn3_program_pix_clk` → `dce112_program_pix_clk`; `bios/command_table2.c::set_pixel_clock_v7` | SetPixelClock uses the selected combo-PHY PLL and physical encoder, 100-Hz units, XTALIN reference, and deep-color resync. DCN3's path leaves the firmware deep-color ratio zero; it differs from the newer DCN3.1 implementation. `SUPPORT_YCBCR420` is assigned by the older DCE110 resource path, not the selected DCN3 path. No flag change is justified by reading the callee alone. |
| Timing and VTG | `optc/dcn10/dcn10_optc.c::optc1_program_timing`, `optc1_set_vtg_params` | **Gap:** VTG was enabled without programming `VCOUNT_INIT` or `FP2`. Program `v_init = v_total - v_front_porch`, `blank_end = v_init - v_active`, `fp2 = max(0, vstartup - blank_end - 1)`. Also clear inherited interlace for this progressive-only path. Test both DCN3.0 and DCN3.1.4 layouts and the pre-VSYNC boundary. |
| MPC output policy | `hwss/dcn20/dcn20_hwseq.c::dcn20_enable_stream_timing` → `mpc/dcn30/dcn30_mpc.c::mpc3_set_out_rate_control` | **Gap:** only multi-stream enable performed the stream-time update. Takeover's `mpc3_mpc_init_single_inst` clears the count, but not rate bit 9. Single-stream now shares the existing update: disable=1, rate=0 before enabling the OPP. |
| OPP/FMT/OCSC and blanking | `dcn20_blank_pixel_data`; `opp2_program_fmt`; `dcn20_program_output_csc` | Owned OPP clock, native dimensions, format/depth/clamp, OCSC, and DPG black. HDMI format is applied before OTG enable. DPG is disabled under the OTG lock when the primary plane starts. |
| OTG enable | `optc/dcn20/dcn20_optc.c::optc2_enable_crtc` | Segment selection, VTG before OTG master enable, disable point 3, one frame before link setup. |
| Physical output destination | `link/link_dpms.c::link_set_dpms_on` → `optc/dcn30/dcn30_optc.c::optc3_set_out_mux` | **Gap:** `OTG_OUT_MUX` was inherited. DCN3.0 owners now explicitly select DIO before encoder attributes. The saved OTG0 snapshot already had this bit clear, so this gap alone does not explain that black-screen boot. |
| FE→OTG and link mode | `enc1_dig_connect_to_otg`; `dcn10_link_encoder_setup`; `setup_dio_stream_attribute` | Route-specific FE source, HDMI DIG mode, stereo synchronization, then STREAM_SETUP and HDMI stream attributes. |
| HDMI stream attributes | `dio/dcn30/dcn30_dio_stream_encoder.c::enc3_stream_encoder_hdmi_set_stream_attribute` | Packet-generation version, keepout, depth, null/GC packets, scrambler, quarter-rate clock above 340 MHz, AVMUTE. NARF uses the firmware STREAM_SETUP path. Linux's fallback FIFO reset belongs to `avoid_vbios_exec_table`, not an additional step after successful firmware setup. |
| InfoFrames | `enc3_stream_encoder_update_hdmi_info_packets`; `dcn30/dcn30_vpg.c::vpg3_update_generic_info_packet` | Packet RAM, conflict handling, immediate update, send/continuous controls and line selection. DCN3.0 VPG has no `vpg_poweron` callback. |
| SCDC and PHY enable order | `link/link_dpms.c::enable_link_hdmi` | SCDC configuration, backend-to-frontend connection, transmitter enable, status read. Above 340 MHz source and sink both select scrambling and a quarter-rate clock. |
| Firmware transmitter parameters | `dio/dcn10/dcn10_link_encoder.c::dcn10_link_encoder_enable_tmds_output`; `bios/command_table2.c::transmitter_control_v1_6/v1_7`; `bios/dce112/command_table_helper2_dce112.c` | Physical PHY, HDMI mode, four lanes, one-based HPD, symbol clock /10, connector 0 and DIG-FE selector 0 match the selected Linux path. FE selection is programmed by the driver. DCN3.0 selects plain `dcn10_link_encoder_enable_tmds_output`, not the optional clock-pattern workaround wrapper. |
| Post-transmitter setup | `link_set_dpms_on`; `dcn20_enable_stream`; `dcn20_unblank_stream` | DIG setup repeated after firmware transmitter control, FE/BE connected, InfoFrames updated, AVMUTE cleared. The inherited `unblank_stream` is DP-only; HDMI does not require DP stream-enable or training. `optc1_set_early_control` is a no-op. |
| Primary plane fetch | `dcn20_program_front_end_for_ctx`, `dcn20_enable_plane`, `dcn20_update_dchubp_dpp` | Power/clock, DPP DTO, conversion/scaler/line buffer, MPC, HUBP VTG selection/surface/DLG/TTU, unblank and unlock. Earlier poisoned-state and lifetime fixes remain. A two-frame underflow check follows. |
| Pixel upload and flips | NARF presentation owners | `upload_back` writes through retained `MmioRegion` mappings. CPU BAR addresses and GPU surface addresses are separate full-width values. No 40-bit truncation or physical-address-as-direct-map use was found in that upload path. |

## Evidence and remaining hardware questions

`target/host-narf/exec-path-20261026/` contains before/after regression logs.
The original exec path fails all three installed-root tests, including the
same `EXECVE-EIO ... InvalidPath ... /` form seen on the desktop. The fix
rejects empty names as `ENOENT`, directories as `EACCES`, and preserves
`ENOTDIR`, `ELOOP` and real filesystem errors. It does not make `/mnt/`
executable, and does not establish that this probe blocked the display.

The saved physical boot reached native 3840×2160 timing and backed SETCRTC.
Older read-only register snapshots show an advancing OTG, unblanked DPG,
no observed HUBP underflow, and matching programmed/in-use surface addresses.
These facts do not establish HDMI reception or a displayed desktop frame.

The existing SCDC sample is taken immediately after transmitter enable,
before final plane unblank. `TMDS_Config = 3` proves the sink accepted the
configuration write. Zero scrambler/lock flags at that point do not establish
settled link status. A second diagnostic sample after the two-frame verify
window now reports `phase=settled` to distinguish a missing clock/channel
lock from bad pixel delivery. It is diagnostic only; read failures do not
tear down a stream.

The subsequent physical run `guest-yhUoZsEl/serial.log` contains both samples:
the early values are zero; the settled scrambler status is 1 and status flags
are 1. Linux `include/drm/display/drm_scdc.h` defines bit 0 as clock detection
and bits 1–3 as channel locks. This sample therefore reports a detected clock
and scrambling, without channel locks. It narrows the link investigation;
it does not establish a visible image or prove the greeter is the blocker.

Board-specific external HDMI retimer/redriver programming is conditional in
Linux's `enable_link_hdmi`. `link_factory.c` gets those `chip_caps` only from
the BIOS integrated-info external display paths. The captured card VBIOS
(`target/host-narf/plasma-rw/gpu-topology-fix/evidence/navi22-vbios.bin`) has a
v2.1 data directory and a zero `integratedsysteminfo` table offset, confirmed
in `vbios-topology.log`. This Linux retimer/redriver path is therefore not
selected for this captured board. NARF has no generic implementation of the
optional path for other boards.

The QEMU 40-bit clamp is a bring-up workaround. A BAR at 14 TiB in a 48-bit
guest is valid MMIO and does not imply that much RAM. Correcting QEMU's
effective width is separately tested; it is not a proven HDMI fix or a
permanent NARF memory-size limit.
