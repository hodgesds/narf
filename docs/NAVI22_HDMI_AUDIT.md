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
| Timing and VTG | `optc/dcn10/dcn10_optc.c::optc1_program_timing`, `optc1_set_vtg_params` | **Fixed:** VTG initialization now programs `v_init = v_total - v_front_porch`, `blank_end = v_init - v_active`, `fp2 = max(0, vstartup - blank_end - 1)`, and clears inherited interlace. Tests cover both DCN3.0 and DCN3.1.4 layouts and the pre-VSYNC boundary. |
| MPC output policy | `hwss/dcn20/dcn20_hwseq.c::dcn20_enable_stream_timing` → `mpc/dcn30/dcn30_mpc.c::mpc3_set_out_rate_control` | **Fixed:** single-stream now shares the multi-stream update: disable=1, rate=0 before enabling the OPP. Takeover's `mpc3_mpc_init_single_inst` alone clears the count, but not rate bit 9. |
| OPP/FMT/OCSC and blanking | `dcn20_blank_pixel_data`; `opp2_program_fmt`; `dcn20_program_output_csc` | Owned OPP clock, native dimensions, format/depth/clamp, OCSC, and DPG black. HDMI format is applied before OTG enable. DPG is disabled under the OTG lock when the primary plane starts. |
| OTG enable | `optc/dcn20/dcn20_optc.c::optc2_enable_crtc` | Segment selection, VTG before OTG master enable, disable point 3, one frame before link setup. |
| Physical output destination | `link/link_dpms.c::link_set_dpms_on` → `optc/dcn30/dcn30_optc.c::optc3_set_out_mux` | **Fixed:** DCN3.0 owners explicitly select DIO before encoder attributes. The saved OTG0 snapshot already had this bit clear, so this omission alone does not explain that black-screen boot. |
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

The later `guest-XtexVHKX/serial.log` reports scrambler status 1 and status
flags 15 after unblank: clock detection and all three channel locks. The
earlier zero-channel sample was not a persistent-link-failure proof. Neither
sample establishes that the intended framebuffer pixels reach the monitor.

## Implementation follow-up

The remaining native TMDS lifecycle work adds:

- Linux's `dcn30_program_gamut_remap` bypass and
  `dcn30_set_mpc_shaper_3dlut(NULL)` RMU release for encoded RGB scanout.
  Output-gamma bypass alone left these independent stages inherited.
  Release is scoped to the MPCC and the physical RMU count; shared mux updates
  are serialized. It does not program unused denorm callbacks as though they
  were required initialization steps.
- Explicit retirement of OTG stereo/frame-packing and OPP stereo-buffer
  dimensions for the admitted progressive 2D modes.
- A complete seven-slot packet programming surface, validated before any
  writes, including optional HDMI Forum, gamut, SPD, HDR and VTEM packets.
  Standard InfoFrames validate version, length and checksum; data-packet
  payload admission remains with the producer. Desktop enable sends NARF SPD,
  AVI and any required vendor packet, and disables absent producers.
- The 1-ms TMDS configuration settling interval specified by the primary
  Linux DRM SCDC helper (`drivers/gpu/drm/display/drm_scdc_helper.c`).
- Reception classification for scrambled and legacy SCDC links, and bounded
  maintenance on both single-stream and multi-stream contexts. Three observed
  bad samples, spaced at least one second apart, permit one normal relight
  per connection. Persistent subsequent failure is reported without an endless
  reset loop or retiring otherwise healthy outputs. An unavailable read is
  unknown, not failed reception.

The existing path still owns EDID/depth/rate admission, 8/10/12-bpc RGB and
YCbCr 4:2:0 selection, PLL/PHY firmware commands, HDMI/DIG/FMT/OCSC,
audio setup, hotplug, pinned scanout, and normal teardown. New tests start
with inherited color/stereo state, exercise all packet slots and rejected
updates, model sink configuration loss, and enforce the recovery budget and
poll cadence. Evidence is in `target/host-narf/hdmi-complete-20261026/`.

This work targets the selected Navi22/DCN3.0 TMDS path. It does not claim
HDMI certification, FRL, HDCP, CEC, or native
Mesa 3D acceptance from register-model success. Physical visible-output
acceptance remains separate.

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

## Native output controls

The native connector path now carries explicit color format, Colorspace,
max bpc and decoded HDR_OUTPUT_METADATA through both single and group
admission. The old Navi22 dispatch ignored these controls. DRM now publishes
only the implemented HDMI connector properties; the shared bookkeeping does
not import DCN401 CRTC color management or plane capabilities.

The comparison against `enc1_stream_encoder_set_stream_attribute_helper`,
`enc3_stream_encoder_hdmi_set_stream_attribute`, `opp1_set_pixel_encoding`,
`dcn3_get_pix_clk_dividers` and `find_color_matrix` adds the encoding-specific
TMDS/packing, FMT, OCSC and AVI handling for 4:4:4 and 4:2:2 and independent
4:2:0 deep-color capabilities. Inherited RGB random dithering is disabled
for every YCbCr encoding. Output CSC updates preserve the other pipes'
coefficient-format bits. Multi-stream PLL sharing now includes the output
format and actual TMDS target; equal timing dimensions alone are insufficient.

Metadata-only changes retain the live timing and transmitter. The pipeline
updates AVI/SPD/vendor/HDR together, and records the captured snapshot after
success. Enable/disable of HDR and format/depth/color-space changes use
normal safe convergence. Both requested and applied state survive detection;
new requests during hardware awaits remain pending. Native TEST_ONLY uses
cached immutable EDID/board/PHY limits, performs no DDC/register writes and
refuses unsupported explicit encodings rather than changing them silently.

These controls signal output metadata; they do not perform tone mapping or
add high-precision framebuffer input to the current 8888 copy presenter.
Physical HDMI acceptance and native 3D remain unverified. FRL, HDCP and
CEC remain unsupported.

## FreeSync and link-loss follow-up — 2026-10-27

The native HDMI path now queries firmware's AMD vendor-block decoder only
for a valid first CTA extension containing AMD's OUI. The serialized DMUB
command, reply offsets, cancellation and missing optional support are covered
by Rust models. Capabilities are cached by full EDID; firmware-owned fields
are not inferred from an unauthenticated software range parser.

The comparison against `optc1_set_drr`, `optc2_setup_manual_trigger`,
`optc1_set_static_screen_control`, `mod_freesync_build_vrr_infopacket` and
`dm_edid_parser_send_cea` connects the native VRR controls to DCN3.0 totals,
TRIGA/static-screen control, flip-trigger strobes and versioned AMD SPD.
HDR-only updates preserve the FreeSync packet. Fixed-mode startup clears
inherited DRR selectors and MID state. Variable-refresh position sampling
includes the completed total inside its frame-counter consistency check;
vblank reporting does not invent nominal frames when hardware is busy.
LFC and dynamic multi-stream rendering remain outside this implementation.

The physical `guest-TFRvPJOz` run reached backed 4K SETCRTC, but both settled
SCDC samples showed scrambler 1 and flags 1: a detected clock without channel
locks. The monitor spent its one automatic relight and reported `Faulted`.
It now continues low-rate observation after that report, and distinguishes a
later `Recovered` lock without authorizing more resets. Reports include the
actual health classification.

Linux enc3's software stream-setup fallback replaces the reset clock-channel
pattern 0x63 with 0x1f. NARF now checks that postcondition around firmware
setup and transmitter enable, repairing only 0x63 or constant zero while
preserving other patterns. This is a source-derived guard, not a measured
cause of the failed boot: the VM had exited before its registers could be
captured. The next bench run captures settled and post-SETCRTC registers
automatically, including frame counters, clock patterns, DRR and MPC state,
and saves available working-Linux display state before VFIO takeover.

Those captures succeeded in `guest-e3rutSQT`. DIG0's clock pattern is already
0x1f in every sample, excluding the reset-pattern hypothesis for this run.
The post-Xorg counter advances from 685 to 725 between snapshot windows
`1793104100.822358006..1793104100.877330275` and
`1793104101.880248962..1793104101.934992655`. This is not consistent with
the requested 60-Hz cadence if the counter increments once per frame; the
sampling windows do not establish the PLL's actual frequency. Totals remain
4000 by 2222, both HUBP addresses agree, and no HUBP underflow is observed.
Working Linux uses the same EDID mode with two 1920-wide frontend slices.
The clock path requires further hardware comparison; no visible-output
acceptance is inferred from these register values.

The same capture confirms that `OTG_V_TOTAL_LAST_USED_BY_DRR` contains 2222,
while the programmed `V_TOTAL` contains 2221. Linux's
`optc2_get_last_used_drr_vtotal` returns the former verbatim. NARF now samples
that status count without adding one, with the captured value in a regression.

## OTG pixel rate — 2026-10-27

Frame count and vertical position from two snapshot pairs about 1.06 s
apart give the OTG's actual rate. `guest-k3wUxt9t` advances 88668 lines
after settling and 88381 lines after Xorg, about 83.6k lines/s. With
H_TOTAL 4000 that is about 334 MHz, or 37.6 Hz, not the requested
533.25 MHz. `guest-e3rutSQT` gives the same rate.

The root launcher now saves the same registers read-only from working
Linux before VFIO takeover, with a timed frame-rate sample
(`guest-OZvqJQdJ/host-linux/registers.txt`). Linux's OTG runs at
533.249 MHz (59.997 Hz) by the same counter method, so the guest
measurement method is sound and the slow NARF OTG is a real defect.
Linux drives the mode on one OTG and one OPP: ODM source select is a single
OPP 0 segment and OTG_H_TIMING_CNTL is 0. The two 1920-wide HUBPs in its
DTN log are an MPC split (MPCC 0 and 5 both feed OPP 0), which halves
DPPCLK. An earlier reading of that log as ODM 2:1 was wrong.

A NARF build that forced ODM 2:1 above 340 MHz on that wrong premise
failed its verification with an OPTC underflow (`otg: true, hubp: 0`).
That policy is removed: HDMI admission uses DML30's ODM decision again,
which keeps this mode on one pipe. The ODM 2:1 support added for it stays
for streams DML30 splits, and is model-verified only:

- SetPixelClock and the DP DTO get the timing's clock divided by the ODM
  segment count (dcn20 `get_pixel_clock_parameters`); the transmitter keeps
  the character rate.
- Both ODM OPPs get FMT and output CSC. Flips arm both HUBPs under the OTG
  master lock, and the cursor is placed per slice.
- Two multi-stream HDMI defects are fixed. The HDMI format stage ran after
  `set_odm_combine` and reset its H divider to bypass. SCDC was not
  forwarded through `Links`, so a scrambled stream failed.

Every register both captures share matches Linux on the HDMI clock path:
DIG0, DPCS0 TX clock, RDPCSTX clock and PHY_CNTL0/1/3/6/8, PHYPLL0 resync,
OTG0_PIXEL_RATE_CNTL. The remaining OTG timing differences (VTG FP2 1 vs 0,
HUBP VREADY_AT_OR_AFTER_VSYNC) do not set the pixel rate. The DCCG blocks
and the PHY's MPLLB settings (PHY_CNTL9..14) were not in the older NARF
captures. The next run records them, including at `phase=transmitter`
so a failed light still leaves a snapshot.

Reading the RDPCSTX control/interrupt registers and the PHY block in one
sweep on the host returned zeros for PHY_CNTL0, which single reads moments
earlier had returned as 0x30314704. The probe no longer sweeps that window;
PHY_CNTL9..14 are single reads taken before any block read.

## Root cause: DENTIST VCO, then DIRTYFB — 2026-10-27

The slow OTG was a DISPCLK/DPPCLK shortfall, not the HDMI clock path. NARF
derived the DENTIST VCO from CLK0_CLK_PLL_REQ (FbMult 49, 4.9 GHz) and
programmed DISPCLK DID 0x23 and DPPCLK DID 0x24 for 560 and 544 MHz.
Linux's DCN3.0 clock manager reads that register through
`CLK_COMMON_MASK_SH_LIST_DCN20_BASE`, which has no FbMult fields, so
`dcn30_get_vco_frequency_from_reg` returns 0 and Linux always uses its
3.65 GHz default. Linux's own dividers confirm it: DID 0x1a for the
561.538 MHz DML clock of 4K60/533.25 and 0x18 for 608.333 MHz at 594 MHz
decode only at 3.65 GHz. At that VCO NARF's DISPCLK was 417 MHz and its
DPPCLK 406 MHz, below the 533.25 MHz pixel rate. The OTG ran at
334.21 MHz (37.60 Hz), the DIG FIFO reported LEVEL_ERROR, and the sink
saw a valid scrambled clock without a usable stream.

With the 3.65 GHz VCO (`guest-I9bkOuGT`), DENTIST is 0x1b191919, the OTG
measures 533.24 MHz (59.995 Hz) against Linux's 533.249 MHz, the DIG FIFO
holds 8-9 with no error, settled SCDC reports clock and all channel locks,
and the boot colour bars appear on the monitor.

The desktop then stayed on the bars. NARF's native amdgpu presenter copies
a dumb framebuffer into its own back buffer at SETCRTC and flips, rather
than scanning the client buffer in place. It had no
`DRM_IOCTL_MODE_DIRTYFB`, so Xorg's modesetting probe failed and it never
reported shadow updates: the only copy was its still-black first frame.
DIRTYFB now presents the framebuffer again on every CRTC showing it
(whole frame; clip rectangles are accepted but not yet used). In
`guest-5nyflrvC` the scanout holds the SDDM greeter and the monitor shows
it.

Linux-parity fixes found on the way, kept: SetPixelClock with a zero clock
(`dce110_clock_source_power_down`, DC_LOG_BIOS-confirmed) on takeover of a
lit DIG, on stream teardown and before a PLL's first stream is programmed;
the ODM-divided SetPixelClock and DP DTO targets; ODM combine after the HDMI
format stage; SCDC forwarded through multi-stream `Links`. The VBIOS image
NARF reads through ROM registers is byte-identical to the host's VFCT copy.
This board's VBIOS has no SetPixelClock bytecode; DMCUB implements the
display command tables itself, and its golden init enables the DCHUB timer
where the bytecode does not.

The sink's EDID limits it to 23-80 Hz (600 MHz max dot clock), with 4K at
60 and 30 Hz; 60 Hz is its highest 4K refresh.

## Kernel-log feedback

Userspace tty output previously entered the kernel log. Printing `dmesg`
therefore appended each record back to the source, with an additional
timestamp on every pass. The shared tty write path now only drives its output
device. A bounded regression reads a kernel record, prints it to both VT and
serial ttys, and requires the log to remain drained; it failed on the original
code. Explicit `/dev/kmsg` injection is retained. This defect can flood logs
and keep a log consumer running, but does not establish the HDMI failure's
cause.
