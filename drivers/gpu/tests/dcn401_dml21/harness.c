/* Linux DML21 reference for amdgpu_dcn401_dml.rs. Drives the DCN4 top level
 * the way DC does for DCN401 (dml21_translation_helper.c), configured to the
 * native admission policy, and prints the values the Rust plan carries.
 *
 * Policy, matching the Rust port:
 *  - one DP SST stream, one unscaled linear 444_32 plane, DML-decided ODM
 *    (dml2_odm_mode_auto, dynamic ODM off), no MPC combine
 *    (mpcc_combine_factor 1), no cursor, DCC, GPUVM, writeback or iflip;
 *  - DET fixed at the staged 320 KiB per pipe with DET reallocation
 *    minimising off;
 *  - DCFCLK/FCLK keep their DPM range, one pinned UCLK level, and PMO never
 *    searches UCLK pstate strategies (switching is disabled natively). PMO's
 *    stutter phase still runs, as it does on Linux.
 *
 * Arguments (kHz unless noted): pclk hact htotal hfp hsync vact vtotal vfp
 * vsync dcfclk_min dcfclk_max fclk_min fclk_max uclk dispclk_max dppclk_max
 * socclk umc_channels pitch_px. Prints "PLAN <values>" or "REJECT"; a plane
 * on several ODM pipes appends them as odm_pipes.h describes.
 *
 * DPPREFCLK is reported as the value mode programming used: Linux's
 * populate_informative re-derives it as (unsigned)(GlobalDPPCLK * 1000),
 * which can truncate the DFS output by 1 kHz. Build with check.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include "dml_top.h"
#include "dml2_internal_shared_types.h"
#include "bounding_boxes/dcn4_soc_bb.h"
#include "odm_pipes.h"

static bool no_uclk_pstate(struct dml2_pmo_init_for_pstate_support_in_out *in_out)
{
	(void)in_out;
	return false;
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
	unsigned long a[19];

	if (argc != 20) {
		fprintf(stderr, "usage: %s <19 values>\n", argv[0]);
		return 2;
	}
	for (int i = 0; i < 19; i++)
		a[i] = strtoul(argv[i + 1], NULL, 0);

	init.dml2_instance = calloc(1, dml2_get_instance_size_bytes());
	init.options.project_id = dml2_project_dcn4x_stage2_auto_drr_svp;
	struct dml2_pmo_options *o = &init.options.pmo_options;
	o->disable_vblank = o->disable_svp = o->disable_drr_var = true;
	o->disable_drr_clamped = o->disable_fams2 = o->disable_dyn_odm = true;
	o->disable_drr_var_when_var_active = o->disable_drr_clamped_when_var_active = true;
	o->disable_dyn_odm_for_multi_stream = o->disable_dyn_odm_for_stream_with_svp = true;
	init.soc_bb = dml2_socbb_dcn401;
	init.soc_bb.qos_parameters = dml_dcn4_variant_a_soc_qos_params;
	init.ip_caps = dml2_dcn401_max_ip_caps;
	struct dml2_soc_state_table *c = &init.soc_bb.clk_table;
	table(&c->dcfclk, a[9], a[10]);
	table(&c->fclk, a[11], a[12]);
	c->uclk.clk_values_khz[0] = a[13];
	c->uclk.num_clk_values = 1;
	table(&c->dispclk, 100000, a[14]);
	table(&c->dppclk, 100000, a[15]);
	table(&c->dtbclk, 100000, 1564000);
	table(&c->socclk, a[16], a[16]);
	c->dram_config.channel_count = a[17];
	if (!dml2_initialize_instance(&init)) {
		puts("INIT FAILED");
		return 1;
	}
	init.dml2_instance->pmo_instance.init_for_uclk_pstate = no_uclk_pstate;
	/* dml2_mcg_dcn4 prunes a UCLK whose fabric/DCF state exceeds the tables;
	 * mode support then indexes an empty table. That is a rejection. */
	if (!init.dml2_instance->min_clk_table.dram_bw_table.num_entries) {
		puts("REJECT");
		return 0;
	}

	cfg.gpuvm_max_page_table_levels = 4;
	cfg.num_streams = 1;
	cfg.num_planes = 1;
	struct dml2_stream_parameters *s = &cfg.stream_descriptors[0];
	struct dml2_timing_cfg *t = &s->timing;
	t->pixel_clock_khz = a[0];
	t->h_active = a[1];
	t->h_total = a[2];
	t->h_front_porch = a[3];
	t->h_sync_width = a[4];
	t->v_active = a[5];
	t->v_total = a[6];
	t->v_front_porch = a[7];
	t->h_blank_end = a[2] - a[3] - a[1];
	t->v_blank_end = a[6] - a[7] - a[5];
	t->bpc = 8;
	t->vblank_nom = a[6] - a[5];
	t->drr_config.disallowed = true;
	s->output.output_format = dml2_444;
	s->output.output_encoder = dml2_dp;
	s->output.output_dp_lane_count = 4;
	s->output.output_disabled = true;
	s->overrides.odm_mode = dml2_odm_mode_auto;
	s->overrides.disable_dynamic_odm = true;
	s->overrides.disable_subvp = true;
	s->overrides.hw.twait_budgeting.fclk_pstate = dml2_twait_budgeting_setting_if_needed;
	s->overrides.hw.twait_budgeting.uclk_pstate = dml2_twait_budgeting_setting_if_needed;
	s->overrides.hw.twait_budgeting.stutter_enter_exit = dml2_twait_budgeting_setting_if_needed;

	struct dml2_plane_parameters *p = &cfg.plane_descriptors[0];
	p->pixel_format = dml2_444_32;
	p->surface.tiling = dml2_sw_linear;
	p->surface.plane0.pitch = a[18];
	p->surface.plane0.width = a[1];
	p->surface.plane0.height = a[5];
	p->composition.viewport.plane0.width = a[1];
	p->composition.viewport.plane0.height = a[5];
	p->composition.scaler_info.plane0.h_ratio = 1.0;
	p->composition.scaler_info.plane0.v_ratio = 1.0;
	p->composition.scaler_info.plane1.h_ratio = 1.0;
	p->composition.scaler_info.plane1.v_ratio = 1.0;
	p->composition.scaler_info.plane0.h_taps = 1;
	p->composition.scaler_info.plane0.v_taps = 1;
	p->composition.scaler_info.plane1.h_taps = 1;
	p->composition.scaler_info.plane1.v_taps = 1;
	p->composition.scaler_info.rect_out_width = a[1];
	p->composition.rect_out_height_spans_vactive = true;
	p->overrides.det_size_override_kb = 320;
	p->overrides.mpcc_combine_factor = 1;
	p->overrides.gpuvm_min_page_size_kbytes = init.soc_bb.gpuvm_min_page_size_kbytes;

	struct dml2_build_mode_programming_in_out mp = {
		.dml2_instance = init.dml2_instance,
		.display_config = &cfg,
		.programming = &prog,
	};
	if (!dml2_build_mode_programming(&mp)) {
		puts("REJECT");
		return 0;
	}
	const struct dml2_core_internal_mode_program *m =
		&init.dml2_instance->core_instance.clean_me_up.mode_lib.mp;
	const struct dml2_dchub_per_pipe_register_set *r = prog.plane_programming[0].pipe_regs[0];
	const union dml2_global_sync_programming *g = &prog.stream_programming[0].global_sync;
	const struct dml2_dchub_watermark_regs *w = &prog.global_regs.wm_regs[0];
	const struct dml2_display_arb_regs *ar = &prog.global_regs.arb_regs;
	const struct dml2_display_dlg_regs *d = &r->dlg_regs;
	const struct dml2_display_ttu_regs *u = &r->ttu_regs;
	unsigned long v[] = {
		prog.min_clocks.dcn4x.dispclk_khz, (unsigned long)(m->GlobalDPPCLK * 1000 + 0.5),
		prog.plane_programming[0].min_clocks.dcn4x.dppclk_khz, prog.min_clocks.dcn4x.deepsleep_dcfclk_khz,
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
		r->det_size, (unsigned long)(prog.display_config.plane_descriptors[0].overrides.reserved_vblank_time_ns / 1000),
	};
	printf("PLAN");
	for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++)
		printf(" %lu", v[i]);
	print_odm_pipes(&prog.plane_programming[0]);
	putchar('\n');
	return 0;
}
