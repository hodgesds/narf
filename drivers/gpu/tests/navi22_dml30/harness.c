/*
 * Host harness: Linux's own DCN3.0 DML (display_mode_vba.c,
 * dcn30/display_mode_vba_30.c, dcn30/display_rq_dlg_calc_30.c and
 * calcs/dcn_calc_math.c, compiled unmodified) driven the way
 * dcn30_validate_bandwidth drives it, for the configurations
 * amdgpu_dml30.rs plans: unscaled linear XRGB8888 planes, one per stream,
 * GPUVM/DCC/writeback off, one 256-wide cursor budgeted or none.
 *
 *   harness <soc: dcfclk_khz dram_mts channels width_bytes max_dispclk_khz
 *            max_dppclk_khz max_phyclk_khz vco_khz refclk_khz> <n>
 *           n x <pclk_khz hact htotal hfp hsync vact vtotal vfp vsync
 *                cursors dsc_slices dsc_bpp_x16 hdmi>
 *
 * The SoC is the single top state the Rust port plans at (num_states = 1);
 * dcn3_0_ip / dcn3_0_soc come from Linux (dcn30_ip_soc.h, extracted from
 * dcn30_fpu.c by check.sh). Policy, as dcn30_internal_validate_bw runs it:
 *   - dcn20_populate_dml_pipes_from_context + dcn30's dm_lb_16, one pipe per
 *     stream; ModeSupport with dm_allow_self_refresh_and_mclk_switch, and
 *     again with dm_allow_self_refresh when that fails or leaves DRAM clock
 *     change unsupported (prefetch mode 2 is never used);
 *   - pipe_split_policy MPC_SPLIT_AVOID (maxMpcComb 0: no MPC combine) and
 *     disable_timing_sync (synchronized_vblank_all_planes false), which the
 *     port does not implement;
 *   - streams ModeSupport puts on ODM 2:1 are split onto two pipes
 *     (dcn30_split_stream_for_mpc_or_odm), repopulated, and planned with
 *     dcn30_fpu_calculate_wm_and_dlg's set A (default latencies) and
 *     dcn20_calculate_dlg_params' DLG/TTU calls.
 *
 * Output: "REJECT" or
 *   PLAN <mode> <dispclk_khz> <dppclk_khz> <deep_sleep_khz> <dram_change>
 *        <wm urgent> <wm trip> <wm sr_enter> <wm sr_exit> <wm dram>
 *        <frac_urg_bw_nom>
 *   then per DML pipe "| <odm> <vstartup> <vupdate_offset> <vupdate_width>
 *        <vready_offset> <dppclk_khz> <ref_freq_to_pix_freq> <refcyc_per_htotal>
 *        <refcyc_h_blank_end> <min_dst_y_next_start> <refcyc_x_after_scaler>
 *        <dst_y_after_scaler> <dst_y_prefetch> <dst_y_per_vm_vblank>
 *        <dst_y_per_row_vblank> <vratio_prefetch> <refcyc_per_pte_group_vblank_l>
 *        <dst_y_per_pte_row_nom_l> <refcyc_per_pte_group_nom_l>
 *        <refcyc_per_line_delivery_l> <refcyc_per_line_delivery_pre_l>
 *        <refcyc_per_req_delivery_l> <refcyc_per_req_delivery_pre_l>
 *        <min_ttu_vblank> <qos_level_high_wm> <vready_after_vcount0>
 *        <refcyc_per_req_delivery_cur0> <refcyc_per_req_delivery_pre_cur0>"
 * Watermarks are hubbub21_program_*'s convert_and_clamp of the set A ns
 * values at the integer DCHUB reference clock in MHz.
 */
#include "dm_services.h"
#include "display_mode_lib.h"
#include "display_mode_vba.h"
#include "dcn30/display_mode_vba_30.h"
#include "dcn30/display_rq_dlg_calc_30.h"
#include <stdlib.h>

#include "dcn30_ip_soc.h"

static const struct dml_funcs dml30_funcs = {
	.validate = dml30_ModeSupportAndSystemConfigurationFull,
	.recalculate = dml30_recalculate,
	.rq_dlg_get_dlg_reg = dml30_rq_dlg_get_dlg_reg,
	.rq_dlg_get_rq_reg = dml30_rq_dlg_get_rq_reg,
};

struct stream {
	unsigned int pclk, hact, htotal, hfp, hsync, vact, vtotal, vfp, vsync;
	unsigned int cursors, dsc_slices, dsc_bpp16, hdmi;
};

static struct display_mode_lib lib;
static display_e2e_pipe_params_st pipes[6];

/* One DML pipe of stream s: ODM slice `slice` of `slices`. */
static void fill(display_e2e_pipe_params_st *p, const struct stream *s,
		 unsigned int slice, unsigned int slices, unsigned int pipe_idx,
		 unsigned int grp, double refclk_mhz)
{
	memset(p, 0, sizeof(*p));
	p->clks_cfg.refclk_mhz = refclk_mhz;
	p->dout.dsc_enable = s->dsc_slices != 0;
	p->dout.dsc_slices = s->dsc_slices;
	p->pipe.src.dcc = false;
	p->pipe.src.dcc_rate = 1;
	p->pipe.dest.synchronized_vblank_all_planes = false;
	p->pipe.dest.synchronize_timings = false;
	p->pipe.dest.hblank_start = s->htotal - s->hfp;
	p->pipe.dest.hblank_end = p->pipe.dest.hblank_start - s->hact;
	p->pipe.dest.vblank_start = s->vtotal - s->vfp;
	p->pipe.dest.vblank_end = p->pipe.dest.vblank_start - s->vact;
	p->pipe.dest.htotal = s->htotal;
	p->pipe.dest.vtotal = s->vtotal;
	p->pipe.dest.hactive = s->hact;
	p->pipe.dest.vactive = s->vact;
	p->pipe.dest.interlaced = 0;
	p->pipe.dest.pixel_rate_mhz = s->pclk / 1000.0;
	p->pipe.dest.otg_inst = grp;
	p->dout.dp_lanes = 4;
	p->dout.dp_rate = dm_dp_rate_na;
	p->dout.is_virtual = 0;
	p->pipe.dest.odm_combine = slices == 2 ? dm_odm_combine_mode_2to1 : dm_odm_combine_mode_disabled;
	p->pipe.src.hsplit_grp = grp;
	p->dout.output_type = s->hdmi ? dm_hdmi : dm_dp;
	p->dout.output_format = dm_444;
	p->dout.output_bpp = s->dsc_slices ? s->dsc_bpp16 / 16.0 : 24;
	p->dout.dsc_input_bpc = 12;
	p->dout.max_audio_sample_rate = 0;
	p->pipe.src.num_cursors = s->cursors ? lib.ip.number_of_cursors : 0;
	/* dcn20_populate_dml_pipes_from_context always passes a 256-wide
	 * cursor, and fetch_pipe_params budgets one whenever cur0_src_width
	 * is set; cursors == 0 models a plane without one. */
	p->pipe.src.cur0_src_width = s->cursors ? 256 : 0;
	p->pipe.src.cur0_bpp = dm_cur_32bit;
	/* The plane branch for an unscaled full-screen linear XRGB8888 plane. */
	p->pipe.src.is_hsplit = slices > 1;
	p->pipe.src.source_scan = dm_horz;
	p->pipe.src.source_rotation = dm_rotation_0;
	p->pipe.src.viewport_y_y = 0;
	p->pipe.src.viewport_x_y = s->hact / slices * slice;
	p->pipe.src.viewport_width = s->hact / slices;
	p->pipe.src.viewport_height = s->vact;
	p->pipe.src.viewport_width_max = s->hact;
	p->pipe.src.viewport_height_max = s->vact;
	p->pipe.src.surface_width_y = s->hact;
	p->pipe.src.surface_height_y = s->vact;
	p->pipe.src.data_pitch = (s->hact * 4 + 255) / 256 * 256 / 4;
	p->pipe.dest.recout_width = s->hact / slices;
	p->pipe.dest.recout_height = s->vact;
	p->pipe.dest.full_recout_height = s->vact;
	p->pipe.dest.full_recout_width = s->hact / slices * slices;
	p->pipe.scale_ratio_depth.lb_depth = dm_lb_16;
	p->pipe.scale_ratio_depth.hscl_ratio = 1.0;
	p->pipe.scale_ratio_depth.hscl_ratio_c = 1.0;
	p->pipe.scale_ratio_depth.vscl_ratio = 1.0;
	p->pipe.scale_ratio_depth.vscl_ratio_c = 1.0;
	p->pipe.scale_ratio_depth.scl_enable = 0;
	p->pipe.scale_taps.htaps = 1;
	p->pipe.scale_taps.vtaps = 1;
	p->pipe.src.macro_tile_size = dm_4k_tile;
	p->pipe.src.sw_mode = dm_sw_linear;
	p->pipe.src.source_format = dm_444_32;
	(void)pipe_idx;
}

/* hubbub21 convert_and_clamp. */
static unsigned int cycles(double us, unsigned int refclk_mhz)
{
	unsigned int ns = (unsigned int)(us * 1000);
	unsigned long long v = (unsigned long long)ns * refclk_mhz / 1000;
	return v > 0x1fffff ? 0x1fffff : (unsigned int)v;
}

int main(int argc, char **argv)
{
	unsigned int soc[9], n, i, k, pipe_cnt, vlevel;
	struct stream st[6];
	unsigned int odm[6];

	if (argc < 11)
		return 2;
	for (i = 0; i < 9; i++)
		soc[i] = strtoul(argv[1 + i], NULL, 10);
	n = strtoul(argv[10], NULL, 10);
	if (n == 0 || n > 6 || argc != 11 + 13 * (int)n)
		return 2;
	for (k = 0; k < n; k++) {
		unsigned int *f = &st[k].pclk;
		for (i = 0; i < 13; i++)
			f[i] = strtoul(argv[11 + 13 * k + i], NULL, 10);
	}

	{
		struct _vcs_dpi_soc_bounding_box_st bb = dcn3_0_soc;
		struct _vcs_dpi_ip_params_st ip = dcn3_0_ip;

		bb.num_states = 1;
		bb.clock_limits[0].state = 0;
		bb.clock_limits[0].dcfclk_mhz = soc[0] / 1000.0;
		bb.clock_limits[0].fabricclk_mhz = soc[0] / 1000.0;
		bb.clock_limits[0].dram_speed_mts = soc[1];
		bb.clock_limits[0].dispclk_mhz = soc[4] / 1000.0;
		bb.clock_limits[0].dppclk_mhz = soc[5] / 1000.0;
		bb.clock_limits[0].phyclk_mhz = soc[6] / 1000.0;
		bb.num_chans = soc[2];
		bb.dram_channel_width_bytes = soc[3];
		bb.dispclk_dppclk_vco_speed_mhz = soc[7] / 1000.0;
		lib.soc = bb;
		lib.ip = ip;
		lib.project = DML_PROJECT_DCN30;
		lib.funcs = dml30_funcs;
	}
	double refclk_mhz = soc[8] / 1000.0;

	/* dcn30_internal_validate_bw: one pipe per stream, mode 0 then 1. */
	for (k = 0; k < n; k++)
		fill(&pipes[k], &st[k], 0, 1, k, k, refclk_mhz);
	/* Prefetch mode 0 first. dcn20_validate_apply_pipe_split_flags under
	 * MPC_SPLIT_AVOID then keeps the unsplit state (maxMpcComb 0) before the
	 * DRAM clock change check reads it; mode 1 when either fails. */
	lib.soc.allow_dram_self_refresh_or_dram_clock_change_in_vblank =
		dm_allow_self_refresh_and_mclk_switch;
	vlevel = dml_get_voltage_level(&lib, pipes, n);
	if (vlevel < lib.soc.num_states && lib.vba.ModeSupport[vlevel][0])
		lib.vba.maxMpcComb = 0;
	if (vlevel == lib.soc.num_states || !lib.vba.ModeSupport[vlevel][0] ||
	    lib.vba.DRAMClockChangeSupport[vlevel][lib.vba.maxMpcComb] == dm_dram_clock_change_unsupported) {
		lib.soc.allow_dram_self_refresh_or_dram_clock_change_in_vblank = dm_allow_self_refresh;
		vlevel = dml_get_voltage_level(&lib, pipes, n);
		if (vlevel < lib.soc.num_states && lib.vba.ModeSupport[vlevel][0])
			lib.vba.maxMpcComb = 0;
	}
	if (getenv("DEBUG"))
		fprintf(stderr, "validate: allow %d vlevel %u mode %u dram %d support %d/%d\n",
			lib.soc.allow_dram_self_refresh_or_dram_clock_change_in_vblank, vlevel,
			lib.vba.PrefetchModePerState[0][0], lib.vba.DRAMClockChangeSupport[0][0],
			lib.vba.ModeSupport[0][0], lib.vba.ModeSupport[0][1]);
	if (vlevel == lib.soc.num_states || !lib.vba.ModeSupport[vlevel][0]) {
		printf("REJECT\n");
		return 0;
	}
	for (k = 0; k < n; k++) {
		if (lib.vba.NoOfDPP[vlevel][0][k] != 1 &&
		    lib.vba.ODMCombineEnablePerState[vlevel][k] == dm_odm_combine_mode_disabled) {
			printf("REJECT\n");
			return 0;
		}
		odm[k] = lib.vba.ODMCombineEnablePerState[vlevel][k];
		if (odm[k] != dm_odm_combine_mode_disabled && odm[k] != dm_odm_combine_mode_2to1) {
			printf("REJECT\n");
			return 0;
		}
	}
	/* Split ODM streams: the primary keeps its index, the secondary pipe
	 * follows it in DML order (pipe_idx order on the board). */
	pipe_cnt = 0;
	for (k = 0; k < n; k++) {
		unsigned int slices = odm[k] == dm_odm_combine_mode_2to1 ? 2 : 1;
		unsigned int grp = pipe_cnt;
		for (i = 0; i < slices; i++, pipe_cnt++)
			fill(&pipes[pipe_cnt], &st[k], i, slices, pipe_cnt, grp, refclk_mhz);
	}
	if (pipe_cnt > 6) {
		printf("REJECT\n");
		return 0;
	}
	lib.vba.VoltageLevel = vlevel;

	/* dcn30_fpu_calculate_wm_and_dlg, set A with the default latencies. */
	{
		double dcfclk = lib.vba.DCFCLKState[vlevel][lib.vba.maxMpcComb];
		bool pstate_en = lib.vba.DRAMClockChangeSupport[vlevel][lib.vba.maxMpcComb] !=
			dm_dram_clock_change_unsupported;
		unsigned int prefetch_mode = lib.vba.PrefetchModePerState[vlevel][lib.vba.maxMpcComb];
		unsigned int ref = soc[8] / 1000;
		double wm_urgent, wm_trip, wm_enter, wm_exit, wm_dram, frac;
		double dispclk, dppclk[6];
		display_dlg_regs_st dlg;
		display_ttu_regs_st ttu;
		unsigned int dram_change;

		if (lib.soc.min_dcfclk > dcfclk)
			dcfclk = lib.soc.min_dcfclk;
		pipes[0].clks_cfg.voltage = vlevel;
		pipes[0].clks_cfg.dcfclk_mhz = dcfclk;
		pipes[0].clks_cfg.socclk_mhz = lib.soc.clock_limits[vlevel].socclk_mhz;

		wm_urgent = get_wm_urgent(&lib, pipes, pipe_cnt);
		wm_enter = get_wm_stutter_enter_exit(&lib, pipes, pipe_cnt);
		wm_exit = get_wm_stutter_exit(&lib, pipes, pipe_cnt);
		wm_dram = get_wm_dram_clock_change(&lib, pipes, pipe_cnt);
		wm_trip = get_wm_memory_trip(&lib, pipes, pipe_cnt);
		frac = get_fraction_of_urgent_bandwidth(&lib, pipes, pipe_cnt);
		/* Set A = set C with no p-state watermark when unsupported. */
		if (!pstate_en)
			wm_dram = 0;

		dispclk = get_dispclk_calculated(&lib, pipes, pipe_cnt);
		for (i = 0; i < pipe_cnt; i++)
			dppclk[i] = get_dppclk_calculated(&lib, pipes, pipe_cnt, i);
		for (i = 0; i < pipe_cnt; i++) {
			pipes[i].clks_cfg.dispclk_mhz = dispclk;
			pipes[i].clks_cfg.dppclk_mhz = dppclk[i];
		}
		dram_change = lib.vba.DRAMClockChangeSupport[vlevel][lib.vba.maxMpcComb] ==
				dm_dram_clock_change_vactive ? 0 :
			lib.vba.DRAMClockChangeSupport[vlevel][lib.vba.maxMpcComb] ==
				dm_dram_clock_change_vblank ? 1 : 2;

		/* dcn20_calculate_dlg_params */
		{
			double max_dpp = 0;
			for (i = 0; i < pipe_cnt; i++)
				if (max_dpp < dppclk[i] * 1000)
					max_dpp = dppclk[i] * 1000;
			printf("PLAN %u %u %u %u %u %u %u %u %u %u %u",
			       prefetch_mode, (unsigned int)(lib.vba.DISPCLK * 1000),
			       (unsigned int)max_dpp,
			       (unsigned int)(lib.vba.DCFCLKDeepSleep * 1000), dram_change,
			       cycles(wm_urgent, ref), cycles(wm_trip, ref), cycles(wm_enter, ref),
			       cycles(wm_exit, ref), cycles(wm_dram, ref),
			       (unsigned int)(frac * 1000));
		}
		for (i = 0; i < pipe_cnt; i++) {
			pipes[i].pipe.dest.vstartup_start = get_vstartup(&lib, pipes, pipe_cnt, i);
			pipes[i].pipe.dest.vupdate_offset = get_vupdate_offset(&lib, pipes, pipe_cnt, i);
			pipes[i].pipe.dest.vupdate_width = get_vupdate_width(&lib, pipes, pipe_cnt, i);
			pipes[i].pipe.dest.vready_offset = get_vready_offset(&lib, pipes, pipe_cnt, i);
		}
		for (i = 0; i < pipe_cnt; i++) {
			memset(&dlg, 0, sizeof(dlg));
			memset(&ttu, 0, sizeof(ttu));
			lib.funcs.rq_dlg_get_dlg_reg(&lib, &dlg, &ttu, pipes, pipe_cnt, i,
						     prefetch_mode != 2, pstate_en, false, false, true);
			printf(" | %u %u %u %u %u %u", pipes[i].pipe.dest.odm_combine ? 2 : 1,
			       pipes[i].pipe.dest.vstartup_start, pipes[i].pipe.dest.vupdate_offset,
			       pipes[i].pipe.dest.vupdate_width, pipes[i].pipe.dest.vready_offset,
			       (unsigned int)(dppclk[i] * 1000));
			printf(" %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u",
			       dlg.ref_freq_to_pix_freq, dlg.refcyc_per_htotal, dlg.refcyc_h_blank_end,
			       dlg.min_dst_y_next_start, dlg.refcyc_x_after_scaler, dlg.dst_y_after_scaler,
			       dlg.dst_y_prefetch, dlg.dst_y_per_vm_vblank, dlg.dst_y_per_row_vblank,
			       dlg.vratio_prefetch, dlg.refcyc_per_pte_group_vblank_l,
			       dlg.dst_y_per_pte_row_nom_l, dlg.refcyc_per_pte_group_nom_l,
			       dlg.refcyc_per_line_delivery_l, dlg.refcyc_per_line_delivery_pre_l,
			       ttu.refcyc_per_req_delivery_l, ttu.refcyc_per_req_delivery_pre_l,
			       ttu.min_ttu_vblank, ttu.qos_level_high_wm, dlg.vready_after_vcount0,
			       ttu.refcyc_per_req_delivery_cur0, ttu.refcyc_per_req_delivery_pre_cur0);
		}
		printf("\n");
		if (getenv("DEBUG"))
			for (k = 0; k < lib.vba.NumberOfActivePlanes; k++)
				fprintf(stderr, "plane %u: dstx %f dsty %f dsc %f slices %f odm %d dpp %u dppclk %f dispclk %f deepsleep %f\n",
					k, lib.vba.DSTXAfterScaler[k], lib.vba.DSTYAfterScaler[k],
					(double)lib.vba.DSCDelay[k], (double)lib.vba.NumberOfDSCSlices[k],
					(int)lib.vba.ODMCombineEnabled[k], lib.vba.DPPPerPlane[k], lib.vba.DPPCLK[k],
					lib.vba.DISPCLK, lib.vba.DCFCLKDeepSleep);
	}
	return 0;
}
