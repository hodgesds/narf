/* Linux DML21 reference for amdgpu_dcn401_dml.rs `admit_all` with scaled and
 * several planes per stream (multi-plane overlay). As harness_multi.c, but
 * every stream carries its own list of planes, each with its surface,
 * SPL's viewport, scale ratios and taps as dml21_translation_helper.c's
 * populate_dml21_plane_config_from_plane_state passes them: the scaler is
 * enabled when a ratio is not 1 or a tap count exceeds one (use_spl), and
 * an RGB plane's chroma values are its luma ones. Every plane keeps the
 * fixed 320 KiB DET and no MPC combine.
 *
 * Arguments: dcfclk_min dcfclk_max fclk_min fclk_max uclk dispclk_max
 * dppclk_max socclk umc_channels, then per stream: pclk hact htotal hfp hsync
 * vact vtotal vfp vsync <planes>, then per plane: surface_width
 * surface_height pitch_px bytes_per_pixel viewport_width viewport_height
 * h_ratio v_ratio h_taps v_taps (ratios in units of 2^-19, SPL's U3.19).
 * Prints "PLAN <62 values>" per plane in argument order on one line (a plane
 * on two ODM pipes followed by them as odm_pipes.h describes), planes
 * separated by " |", or "REJECT". FMT420, DSC and DP2P0 apply to every
 * stream as in harness_multi.c; RAISED too.
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
	unsigned long s9[9];
	int a = 1;

#define NEXT() (a < argc ? strtoul(argv[a++], NULL, 0) : (fprintf(stderr, "short arguments\n"), exit(2), 0UL))
	if (argc < 30) {
		fprintf(stderr, "usage: %s <9 soc values> (<10 stream values> <planes> <10 per plane>)...\n", argv[0]);
		return 2;
	}
	for (int i = 0; i < 9; i++)
		s9[i] = NEXT();

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
	table(&c->dcfclk, s9[0], s9[1]);
	table(&c->fclk, s9[2], s9[3]);
	c->uclk.clk_values_khz[0] = s9[4];
	c->uclk.num_clk_values = 1;
	table(&c->dispclk, 100000, s9[5]);
	table(&c->dppclk, 100000, s9[6]);
	table(&c->dtbclk, 100000, 1564000);
	table(&c->socclk, s9[7], s9[7]);
	c->dram_config.channel_count = s9[8];
	if (!dml2_initialize_instance(&init)) {
		puts("INIT FAILED");
		return 1;
	}
	init.dml2_instance->pmo_instance.init_for_uclk_pstate = no_uclk_pstate;
	if (!init.dml2_instance->min_clk_table.dram_bw_table.num_entries) {
		puts("REJECT");
		return 0;
	}

	cfg.gpuvm_max_page_table_levels = 4;
	int n = 0, planes = 0;
	while (a < argc) {
		if (n == 4 || planes == 4) {
			fprintf(stderr, "at most four streams and planes\n");
			return 2;
		}
		unsigned long t9[9];
		for (int i = 0; i < 9; i++)
			t9[i] = NEXT();
		unsigned long count = NEXT();
		struct dml2_stream_parameters *s = &cfg.stream_descriptors[n];
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
		t->drr_config.disallowed = true;
		s->output.output_format = getenv("FMT420") ? dml2_420 : dml2_444;
		s->output.output_encoder = getenv("FMT420") ? dml2_hdmi :
			getenv("DP2P0") ? dml2_dp2p0 : dml2_dp;
		s->output.output_dp_lane_count = 4;
		s->output.output_disabled = true;
		if (getenv("DSC")) {
			unsigned int slices = 0, bpp_x16 = 0;
			sscanf(getenv("DSC"), "%u %u", &slices, &bpp_x16);
			t->dsc.enable = dml2_dsc_enable;
			t->dsc.overrides.num_slices = slices;
			t->dsc.dsc_compressed_bpp_x16 = bpp_x16;
		}
		s->overrides.odm_mode = dml2_odm_mode_auto;
		s->overrides.disable_dynamic_odm = true;
		s->overrides.disable_subvp = true;
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

			p->stream_index = n;
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
			p->composition.rect_out_height_spans_vactive = true;
			p->overrides.det_size_override_kb = 320;
			p->overrides.mpcc_combine_factor = 1;
			p->overrides.gpuvm_min_page_size_kbytes = init.soc_bb.gpuvm_min_page_size_kbytes;
		}
		n++;
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
	const struct dram_bw_to_min_clk_table_entry *e =
		&init.dml2_instance->min_clk_table.dram_bw_table.entries[0];
	if (getenv("RAISED") && (prog.min_clocks.dcn4x.active.dcfclk_khz > e->min_dcfclk_khz ||
				 prog.min_clocks.dcn4x.active.fclk_khz > e->min_fclk_khz)) {
		puts("RAISED");
		return 0;
	}
	const struct dml2_core_internal_mode_program *m =
		&init.dml2_instance->core_instance.clean_me_up.mode_lib.mp;
	printf("PLAN");
	for (int k = 0; k < planes; k++) {
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
		if (k)
			printf(" |");
		for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++)
			printf(" %lu", v[i]);
		print_odm_pipes(&prog.plane_programming[k]);
	}
	putchar('\n');
	return 0;
}
