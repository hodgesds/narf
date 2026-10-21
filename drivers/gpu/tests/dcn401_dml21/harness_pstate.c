/* Linux DML21 UCLK P-state reference for amdgpu_dcn401_pstate.rs.
 *
 * As harness_planes.c (up to four streams, each with its own planes: linear
 * RGB surfaces with SPL's viewport, ratios and taps, every plane with the
 * fixed 320 KiB DET, DML-decided ODM and DC's auto MPC combine factor), but
 * with DCN401's PMO policy left on: the UCLK P-state phase searches
 * dml2_pmo_dcn4_fams2's strategy lists, and DPMM maps the result to the
 * SoC's UCLK DPM levels.
 *
 * Arguments: dcfclk_min dcfclk_max fclk_min fclk_max dispclk_max dppclk_max
 * socclk umc_channels, the UCLK level count n, n ascending UCLK levels, the
 * FAMS2 flag, the stream count, then per stream: pclk hact htotal hfp hsync
 * vact vtotal vfp vsync, its output (0: DP SST RGB, 1: HDMI YCbCr 4:2:0)
 * and plane count, then per plane: surface_width surface_height pitch_px
 * bytes_per_pixel viewport_width viewport_height h_ratio v_ratio h_taps
 * v_taps (ratios in units of 2^-19).
 *
 * A FAMS2 flag of 1 is dml21_populate_pmo_options with the DMUB firmware's
 * FAMS version matching (dc->debug.fams2_config.bits.enable): SubVP, DRR and
 * FAMS2 strategies allowed. With 0 they are disabled, as DC disables them
 * when the firmware does not report FAMS 2.1. Every stream has fixed
 * refresh (no DRR).
 *
 * Prints "REJECT", or one line:
 *   PSTATE <uclk_pstate_supported> <fclk_pstate_supported> <stage3 success>
 *     <min clk index> <fams2_required> <method per stream>...
 *     <active uclk fclk dcfclk> <idle uclk fclk dcfclk>
 *     | <plan values per plane, as harness_planes, planes split by " |">
 *     | FAMS2 <per stream: type allow_start allow_end vblank_start vblank_end
 *       otg_vline_time_ns scheduling contention vline_ack allow_to_target
 *       drr_keepout max_vtotal min_ttu_vblank_usable clamp_vtotal_min
 *       vactive_det_fill_delay_lines>...
 *     | CANDIDATES <the chosen index> <each candidate's methods, "," between
 *       streams>...
 * The plan and FAMS2 fields come only with uclk_pstate_supported.
 */
#include <stdio.h>
#include <stdlib.h>
#include "dml_top.h"
#include "dml2_internal_shared_types.h"
#include "bounding_boxes/dcn4_soc_bb.h"
#include "odm_pipes.h"

static enum dml2_source_format_class format_of(unsigned long bytes)
{
	switch (bytes) {
	case 2:
		return dml2_444_16;
	case 8:
		return dml2_444_64;
	case 4:
		return dml2_444_32;
	}
	fprintf(stderr, "bytes per pixel must be 2, 4 or 8\n");
	exit(2);
}

static void table(struct dml2_clk_table *t, unsigned long lo, unsigned long hi)
{
	t->clk_values_khz[0] = lo;
	t->clk_values_khz[1] = hi;
	t->num_clk_values = 2;
}

int main(int argc, char **argv)
{
	static struct dml2_initialize_instance_in_out init;
	static struct dml2_display_cfg cfg;
	static struct dml2_display_cfg_programming prog;
	unsigned long s8[8], uclk[8];
	int a = 1;

#define NEXT() (a < argc ? strtoul(argv[a++], NULL, 0) : (fprintf(stderr, "short arguments\n"), exit(2), 0UL))
	if (argc == 2 && !strcmp(argv[1], "--strategies")) {
		/* pmo_dcn4_fams2_initialize's expanded lists: one line per
		 * display count, each strategy's methods ("," between streams)
		 * with "+" for allow_state_increase. */
		init.dml2_instance = calloc(1, dml2_get_instance_size_bytes());
		init.options.project_id = dml2_project_dcn4x_stage2_auto_drr_svp;
		init.soc_bb = dml2_socbb_dcn401;
		init.soc_bb.qos_parameters = dml_dcn4_variant_a_soc_qos_params;
		init.ip_caps = dml2_dcn401_max_ip_caps;
		table(&init.soc_bb.clk_table.dcfclk, 200000, 1564000);
		table(&init.soc_bb.clk_table.fclk, 300000, 2500000);
		if (!dml2_initialize_instance(&init)) {
			puts("INIT FAILED");
			return 1;
		}
		struct dml2_pmo_init_data *d = &init.dml2_instance->pmo_instance.init_data;
		const struct dml2_pmo_pstate_strategy *lists[4] = {
			d->pmo_dcn4.expanded_strategy_list_1_display, d->pmo_dcn4.expanded_strategy_list_2_display,
			d->pmo_dcn4.expanded_strategy_list_3_display, d->pmo_dcn4.expanded_strategy_list_4_display,
		};
		for (int k = 0; k < 4; k++) {
			printf("%d", k + 1);
			for (unsigned int i = 0; i < d->pmo_dcn4.num_expanded_strategies_per_list[k]; i++) {
				putchar(' ');
				for (int j = 0; j <= k; j++)
					printf("%s%d", j ? "," : "", lists[k][i].per_stream_pstate_method[j]);
				if (lists[k][i].allow_state_increase)
					putchar('+');
			}
			putchar('\n');
		}
		return 0;
	}
	for (int i = 0; i < 8; i++)
		s8[i] = NEXT();
	int levels = (int)NEXT();
	if (levels < 1 || levels > 8) {
		fprintf(stderr, "one to eight UCLK levels\n");
		return 2;
	}
	for (int i = 0; i < levels; i++)
		uclk[i] = NEXT();
	bool fams2 = NEXT() != 0;
	int n = (int)NEXT();
	if (n < 1 || n > 4) {
		fprintf(stderr, "one to four streams\n");
		return 2;
	}

	init.dml2_instance = calloc(1, dml2_get_instance_size_bytes());
	init.options.project_id = dml2_project_dcn4x_stage2_auto_drr_svp;
	/* dml21_populate_pmo_options for DCN401's debug defaults. */
	struct dml2_pmo_options *o = &init.options.pmo_options;
	o->disable_dyn_odm = true;
	o->disable_dyn_odm_for_multi_stream = true;
	o->disable_dyn_odm_for_stream_with_svp = true;
	o->disable_vblank = false;
	o->disable_svp = !fams2;
	o->disable_drr_clamped = !fams2;
	o->disable_drr_var = !fams2;
	o->disable_fams2 = !fams2;
	o->disable_drr_var_when_var_active = false;
	o->disable_drr_clamped_when_var_active = false;
	init.soc_bb = dml2_socbb_dcn401;
	init.soc_bb.qos_parameters = dml_dcn4_variant_a_soc_qos_params;
	init.ip_caps = dml2_dcn401_max_ip_caps;
	struct dml2_soc_state_table *c = &init.soc_bb.clk_table;
	table(&c->dcfclk, s8[0], s8[1]);
	table(&c->fclk, s8[2], s8[3]);
	for (int i = 0; i < levels; i++)
		c->uclk.clk_values_khz[i] = uclk[i];
	c->uclk.num_clk_values = levels;
	table(&c->dispclk, 100000, s8[4]);
	table(&c->dppclk, 100000, s8[5]);
	table(&c->dtbclk, 100000, 1564000);
	table(&c->socclk, s8[6], s8[6]);
	c->dram_config.channel_count = s8[7];
	if (!dml2_initialize_instance(&init)) {
		puts("INIT FAILED");
		return 1;
	}
	if (!init.dml2_instance->min_clk_table.dram_bw_table.num_entries) {
		puts("REJECT");
		return 0;
	}

	cfg.gpuvm_max_page_table_levels = 4;
	int planes = 0;
	for (int k = 0; k < n; k++) {
		unsigned long t9[9];
		for (int i = 0; i < 9; i++)
			t9[i] = NEXT();
		bool ycbcr420 = NEXT() != 0;
		unsigned long count = NEXT();
		struct dml2_stream_parameters *s = &cfg.stream_descriptors[k];
		struct dml2_timing_cfg *t = &s->timing;
		t->pixel_clock_khz = t9[0];
		t->h_active = t9[1];
		t->h_total = t9[2];
		t->h_front_porch = t9[3];
		t->h_sync_width = t9[4];
		t->v_active = t9[5];
		t->v_total = t9[6];
		t->v_front_porch = t9[7];
		t->h_blank_end = t9[2] - t9[3] - t9[1];
		t->v_blank_end = t9[6] - t9[7] - t9[5];
		t->bpc = 8;
		t->vblank_nom = t9[6] - t9[5];
		/* A fixed-refresh stream: no ignore_msa_timing_param, freesync
		 * not allowed. */
		t->drr_config.enabled = false;
		t->drr_config.disallowed = true;
		s->output.output_format = ycbcr420 ? dml2_420 : dml2_444;
		s->output.output_encoder = ycbcr420 ? dml2_hdmi : dml2_dp;
		s->output.output_dp_lane_count = 4;
		s->output.output_disabled = true;
		s->overrides.odm_mode = dml2_odm_mode_auto;
		s->overrides.disable_dynamic_odm = true;
		s->overrides.disable_subvp = false;
		s->overrides.hw.twait_budgeting.fclk_pstate = dml2_twait_budgeting_setting_if_needed;
		s->overrides.hw.twait_budgeting.uclk_pstate = dml2_twait_budgeting_setting_if_needed;
		s->overrides.hw.twait_budgeting.stutter_enter_exit = dml2_twait_budgeting_setting_if_needed;

		for (unsigned long j = 0; j < count; j++) {
			unsigned long v[10];
			if (planes == 4) {
				fprintf(stderr, "at most four planes\n");
				return 2;
			}
			for (int i = 0; i < 10; i++)
				v[i] = NEXT();
			struct dml2_plane_parameters *p = &cfg.plane_descriptors[planes++];
			double h = v[6] / 524288.0, vr = v[7] / 524288.0;
			bool enabled = v[6] != 524288 || v[7] != 524288 || v[8] > 1 || v[9] > 1;

			p->stream_index = k;
			p->pixel_format = format_of(v[3]);
			p->surface.tiling = dml2_sw_linear;
			p->surface.plane0.pitch = v[2];
			p->surface.plane0.width = v[0];
			p->surface.plane0.height = v[1];
			p->composition.viewport.plane0.width = v[4];
			p->composition.viewport.plane0.height = v[5];
			p->composition.viewport.plane1.width = v[4];
			p->composition.viewport.plane1.height = v[5];
			p->composition.scaler_info.enabled = enabled;
			p->composition.scaler_info.plane0.h_ratio = enabled ? h : 1.0;
			p->composition.scaler_info.plane0.v_ratio = enabled ? vr : 1.0;
			p->composition.scaler_info.plane1.h_ratio = enabled ? h : 1.0;
			p->composition.scaler_info.plane1.v_ratio = enabled ? vr : 1.0;
			p->composition.scaler_info.plane0.h_taps = v[8];
			p->composition.scaler_info.plane0.v_taps = v[9];
			p->composition.scaler_info.plane1.h_taps = v[8];
			p->composition.scaler_info.plane1.v_taps = v[9];
			p->composition.scaler_info.rect_out_width = t9[1];
			/* populate_dml21_plane_config_from_plane_state: the plane's
			 * destination covers the stream's height. */
			p->composition.rect_out_height_spans_vactive =
				(unsigned long)(v[5] / vr + 0.5) >= t9[5];
			p->overrides.det_size_override_kb = 320;
			p->overrides.mpcc_combine_factor = 0;
			p->overrides.gpuvm_min_page_size_kbytes = init.soc_bb.gpuvm_min_page_size_kbytes;
		}
	}
	if (a != argc) {
		fprintf(stderr, "trailing arguments\n");
		return 2;
	}
	cfg.num_streams = n;
	cfg.num_planes = planes;

	struct dml2_build_mode_programming_in_out mp = {
		.dml2_instance = init.dml2_instance,
		.display_config = &cfg,
		.programming = &prog,
	};
	if (!dml2_build_mode_programming(&mp)) {
		puts("REJECT");
		return 0;
	}
	const struct display_configuation_with_meta *meta =
		&init.dml2_instance->scratch.build_mode_programming_locals.base_display_config_with_meta;
	int index = meta->stage3.success ? meta->stage3.min_clk_index_for_latency :
		meta->stage1.min_clk_index_for_latency;
	printf("PSTATE %d %d %d %d %d", prog.uclk_pstate_supported, prog.fclk_pstate_supported,
	       meta->stage3.success, index, prog.fams2_required);
	for (int k = 0; k < n; k++)
		printf(" %d", prog.stream_programming[k].uclk_pstate_method);
	printf(" %lu %lu %lu %lu %lu %lu",
	       prog.min_clocks.dcn4x.active.uclk_khz, prog.min_clocks.dcn4x.active.fclk_khz,
	       prog.min_clocks.dcn4x.active.dcfclk_khz, prog.min_clocks.dcn4x.idle.uclk_khz,
	       prog.min_clocks.dcn4x.idle.fclk_khz, prog.min_clocks.dcn4x.idle.dcfclk_khz);
	const struct dml2_core_internal_mode_program *m =
		&init.dml2_instance->core_instance.clean_me_up.mode_lib.mp;
	for (int k = 0; k < planes && prog.uclk_pstate_supported; k++) {
		const struct dml2_dchub_per_pipe_register_set *r = prog.plane_programming[k].pipe_regs[0];
		const union dml2_global_sync_programming *g =
			&prog.stream_programming[cfg.plane_descriptors[k].stream_index].global_sync;
		const struct dml2_dchub_watermark_regs *w = &prog.global_regs.wm_regs[0];
		const struct dml2_display_arb_regs *ar = &prog.global_regs.arb_regs;
		const struct dml2_display_dlg_regs *d = &r->dlg_regs;
		const struct dml2_display_ttu_regs *u = &r->ttu_regs;
		unsigned long v[] = {
			prog.min_clocks.dcn4x.dispclk_khz, (unsigned long)(m->GlobalDPPCLK * 1000 + 0.5),
			prog.plane_programming[k].min_clocks.dcn4x.dppclk_khz, prog.min_clocks.dcn4x.deepsleep_dcfclk_khz,
			prog.min_clocks.dcn4x.active.dcfclk_khz, prog.min_clocks.dcn4x.active.fclk_khz,
			prog.min_clocks.dcn4x.active.uclk_khz, prog.min_clocks.dcn4x.socclk_khz,
			g->dcn4x.vstartup_lines, g->dcn4x.vupdate_offset_pixels, g->dcn4x.vupdate_vupdate_width_pixels,
			g->dcn4x.vready_offset_pixels, g->dcn4x.pstate_keepout_start_lines,
			d->refcyc_h_blank_end, d->dlg_vblank_end, d->min_dst_y_next_start, d->refcyc_per_htotal,
			d->refcyc_x_after_scaler, d->dst_y_after_scaler, d->dst_y_prefetch, d->dst_y_per_vm_vblank,
			d->dst_y_per_row_vblank, d->ref_freq_to_pix_freq, d->vratio_prefetch, d->vratio_prefetch_c,
			d->refcyc_per_line_delivery_pre_l, d->refcyc_per_line_delivery_l, d->vready_after_vcount0,
			d->dst_y_delta_drq_limit, d->dmdata_dl_delta,
			u->qos_level_low_wm, u->qos_level_high_wm, u->min_ttu_vblank, u->qos_level_flip,
			u->refcyc_per_req_delivery_l, u->refcyc_per_req_delivery_pre_l, u->qos_level_fixed_l, u->qos_level_fixed_c,
			w->urgent, w->sr_enter, w->sr_exit, w->uclk_pstate, w->fclk_pstate, w->temp_read_or_ppt, w->usr,
			w->refcyc_per_trip_to_mem, w->refcyc_per_meta_trip_to_mem, w->frac_urg_bw_flip, w->frac_urg_bw_nom,
			w->frac_urg_bw_mall,
			ar->max_req_outstanding, ar->min_req_outstanding, ar->sat_level_us, ar->compbuf_reserved_space_kbytes,
			ar->compbuf_size, ar->sdpif_request_rate_limit, ar->dcfclk_deep_sleep_hysteresis,
			ar->pstate_stall_threshold, ar->hvm_max_qos_commit_threshold, ar->hvm_min_req_outstand_commit_threshold,
			r->det_size, (unsigned long)(prog.display_config.plane_descriptors[k].overrides.reserved_vblank_time_ns / 1000),
		};
		printf(" |");
		for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++)
			printf(" %lu", v[i]);
		print_odm_pipes(&prog.plane_programming[k]);
	}
	if (prog.uclk_pstate_supported)
		printf(" | FAMS2");
	for (int k = 0; k < n && prog.uclk_pstate_supported; k++) {
		const struct dmub_fams2_cmd_stream_static_base_state *b =
			&prog.stream_programming[k].fams2_base_params.stream_v1.base;
		const union dmub_fams2_cmd_stream_static_sub_state *ss =
			&prog.stream_programming[k].fams2_sub_params.stream_v1.sub_state;
		printf(" %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u", b->type, b->allow_start_otg_vline,
		       b->allow_end_otg_vline, b->vblank_start, b->vblank_end, b->otg_vline_time_ns,
		       b->scheduling_delay_otg_vlines, b->contention_delay_otg_vlines,
		       b->vline_int_ack_delay_otg_vlines, b->allow_to_target_delay_otg_vlines,
		       b->drr_keepout_otg_vline, b->max_vtotal, b->config.bits.min_ttu_vblank_usable,
		       b->config.bits.clamp_vtotal_min, ss->legacy.vactive_det_fill_delay_otg_vlines);
	}
	const struct dml2_pmo_scratch *ps = &init.dml2_instance->pmo_instance.scratch;
	printf(" | CANDIDATES %d", ps->pmo_dcn4.cur_pstate_candidate);
	for (int i = 0; i < ps->pmo_dcn4.num_pstate_candidates; i++) {
		putchar(' ');
		for (int k = 0; k < n; k++)
			printf("%s%d", k ? "," : "", ps->pmo_dcn4.pstate_strategy_candidates[i].per_stream_pstate_method[k]);
	}
	putchar('\n');
	return 0;
}
