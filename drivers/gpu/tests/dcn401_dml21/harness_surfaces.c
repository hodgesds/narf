/* Linux DML21 reference for amdgpu_dcn401_dml.rs `admit_all` with GFX12
 * tiled, DCC and 4:2:0 video planes. As harness_planes.c, but every plane
 * also carries its source format, GFX12 swizzle, DCC enable and rotation as
 * dml21_translation_helper.c's populate_dml21_surface_config_from_plane_state
 * and populate_dml21_plane_config_from_plane_state pass them (dcc_rate 2.0,
 * fraction_of_zero_size_request_plane0 the independent-64B flag amdgpu_dm
 * sets for DCC_MAX_COMPRESSED_BLOCK 64B, no meta pitch on GFX12), and a
 * 4:2:0 plane its chroma surface, viewport, ratios and taps (an RGB plane's
 * chroma values are its luma ones, as in harness_planes.c).
 *
 * Arguments: as harness_planes.c, but per plane: surface_width
 * surface_height pitch_px bytes_per_pixel viewport_width viewport_height
 * h_ratio v_ratio h_taps v_taps source swizzle dcc rotation c_width c_height
 * c_pitch c_viewport_width c_viewport_height c_h_ratio c_v_ratio c_h_taps
 * c_v_taps (the chroma values 0 for RGB). source is 0 RGB (bytes_per_pixel
 * 2, 4 or 8), 1 dml2_420_8, 2 dml2_420_10; swizzle 0 linear, 1 256B_2D,
 * 2 4KB_2D, 3 64KB_2D, 4 256KB_2D; dcc 0 off, 1 on with independent 64B
 * blocks, 2 on without; rotation 0-3 (dml2_rotation_angle).
 * Prints as harness_planes.c, each plane's 62 values followed by 56 more:
 * refcyc_per_line_delivery_pre_c refcyc_per_line_delivery_c
 * refcyc_per_req_delivery_pre_c refcyc_per_req_delivery_c, the rq_regs of
 * luma then chroma (chunk_size min_chunk_size meta_chunk_size
 * min_meta_chunk_size dpte_group_size mpte_group_size swath_height
 * pte_row_height_linear), drq/prq/mrq/crq_expansion_mode plane1_base_address
 * unbounded_request_enabled, the arbiter's
 * allow_sdpif_rate_limit_when_cstate_req, the plane's mcache allocation
 * (num_mcaches_plane0/1, all DML2_MAX_MCACHES + 1 x offsets of plane 0 then
 * plane 1, all DML2_MAX_MCACHES + 1 global ids of plane 0 then plane 1,
 * last_slice_sharing.plane0_plane1) and, for four pipes, the main mcache
 * registers dml2_build_mcache_programming derives (p0 then p1: first id,
 * second id, split location; zeros past the plane's pipes), each pipe's
 * viewports SPL's on that pipe's ODM or MPC slice (spl_viewport.c), as
 * dml21_get_pipe_mcache_config takes them from its scaler data.
 * With MPC_AUTO set, every plane's mpcc_combine_factor is DC's auto (0):
 * a plane one DPP cannot carry takes two (MPC combine, "/2").
 */
#include <stdio.h>
#include <stdlib.h>
#include "dml_top.h"
#include "dml2_internal_shared_types.h"
#include "bounding_boxes/dcn4_soc_bb.h"
#include "odm_pipes.h"

int narf_spl_viewports(int src_w, int src_h, int dst_w, int dst_h, int stream_w, int stream_h,
		       int odm_x, int odm_w, int mpc_index, int mpc_count, int rotation,
		       int video, int vp[4], int vp_c[4]);

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
		fprintf(stderr, "usage: %s <9 soc values> (<10 stream values> <planes> <23 per plane>)...\n", argv[0]);
		return 2;
	}
	for (int i = 0; i < 9; i++)
		s9[i] = NEXT();

	init.dml2_instance = calloc(1, dml2_get_instance_size_bytes());
	init.options.project_id = dml2_project_dcn4x_stage2_auto_drr_svp;
	struct dml2_pmo_options *o = &init.options.pmo_options;
	o->disable_vblank = o->disable_svp = o->disable_drr_var = true;
	o->disable_drr_clamped = o->disable_fams2 = true;
	o->disable_drr_var_when_var_active = o->disable_drr_clamped_when_var_active = true;
	/* dml21_populate_pmo_options as DC runs DCN401
	 * (minimize_dispclk_using_odm): dynamic ODM on for one stream, so
	 * pmo_dcn4_fams2_optimize_dcc_mcache may raise a single ODM stream's
	 * combine factor, off for several or with SubVP. */
	o->disable_dyn_odm = false;
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
		/* DC clears this per stream for DCN401's single-display 2:1 ODM
		 * policy (enable_single_display_2to1_odm_policy), which drives
		 * the Vmin phase's dynamic ODM. NARF does not port that phase:
		 * every stream keeps it set, so the Vmin phase leaves ODM alone. */
		s->overrides.disable_dynamic_odm = true;
		s->overrides.disable_subvp = true;
		s->overrides.hw.twait_budgeting.fclk_pstate = dml2_twait_budgeting_setting_if_needed;
		s->overrides.hw.twait_budgeting.uclk_pstate = dml2_twait_budgeting_setting_if_needed;
		s->overrides.hw.twait_budgeting.stutter_enter_exit = dml2_twait_budgeting_setting_if_needed;

		for (unsigned long j = 0; j < count; j++) {
			unsigned long v[23];
			if (planes == 4) {
				fprintf(stderr, "at most four planes\n");
				return 2;
			}
			for (int i = 0; i < 23; i++)
				v[i] = NEXT();
			struct dml2_plane_parameters *p = &cfg.plane_descriptors[planes++];
			bool yuv = v[10] != 0;
			/* chroma: width height pitch vp_w vp_h h_ratio v_ratio h_taps v_taps */
			unsigned long c[9] = { v[0], v[1], v[2], v[4], v[5], v[6], v[7], v[8], v[9] };
			if (yuv)
				for (int i = 0; i < 9; i++)
					c[i] = v[14 + i];
			double h = v[6] / 524288.0, vr = v[7] / 524288.0;
			double hc = c[5] / 524288.0, vc = c[6] / 524288.0;
			bool enabled = v[6] != 524288 || v[7] != 524288 || v[8] > 1 || v[9] > 1 ||
				c[5] != 524288 || c[6] != 524288 || c[7] > 1 || c[8] > 1;
			static const enum dml2_swizzle_mode sw[] = { dml2_sw_linear, dml2_sw_256b_2d,
				dml2_sw_4kb_2d, dml2_sw_64kb_2d, dml2_sw_256kb_2d };

			if (v[10] > 2 || v[11] > 4 || v[12] > 2 || v[13] > 3) {
				fprintf(stderr, "bad source, swizzle, dcc or rotation\n");
				return 2;
			}
			p->stream_index = n;
			p->pixel_format = v[10] == 1 ? dml2_420_8 : v[10] == 2 ? dml2_420_10 : format_of(v[3]);
			p->surface.tiling = sw[v[11]];
			p->surface.dcc.enable = v[12] != 0;
			p->surface.dcc.informative.dcc_rate_plane0 = 2.0;
			p->surface.dcc.informative.dcc_rate_plane1 = 2.0;
			p->surface.dcc.informative.fraction_of_zero_size_request_plane0 = v[12] == 1;
			p->surface.dcc.informative.fraction_of_zero_size_request_plane1 = 0;
			p->composition.rotation_angle = (enum dml2_rotation_angle)v[13];
			p->surface.plane0.pitch = v[2];
			p->surface.plane0.width = v[0];
			p->surface.plane0.height = v[1];
			if (yuv) {
				p->surface.plane1.pitch = c[2];
				p->surface.plane1.width = c[0];
				p->surface.plane1.height = c[1];
			}
			p->composition.viewport.plane0.width = v[4];
			p->composition.viewport.plane0.height = v[5];
			p->composition.viewport.plane1.width = c[3];
			p->composition.viewport.plane1.height = c[4];
			p->composition.scaler_info.enabled = enabled;
			p->composition.scaler_info.plane0.h_ratio = enabled ? h : 1.0;
			p->composition.scaler_info.plane0.v_ratio = enabled ? vr : 1.0;
			p->composition.scaler_info.plane1.h_ratio = enabled ? hc : 1.0;
			p->composition.scaler_info.plane1.v_ratio = enabled ? vc : 1.0;
			p->composition.scaler_info.plane0.h_taps = v[8];
			p->composition.scaler_info.plane0.v_taps = v[9];
			p->composition.scaler_info.plane1.h_taps = c[7];
			p->composition.scaler_info.plane1.v_taps = c[8];
			p->composition.scaler_info.rect_out_width = t9[1];
			p->composition.rect_out_height_spans_vactive = true;
			p->overrides.det_size_override_kb = 320;
			/* MPC_AUTO: DC's auto factor (0), as dml21_translation_helper
			 * leaves it; otherwise MPC combine is off (factor 1), except
			 * where pmo_dcn4_fams2_optimize_dcc_mcache splits a DCC plane
			 * whose mcaches one pipe cannot place. */
			p->overrides.mpcc_combine_factor = getenv("MPC_AUTO") ? 0 : 1;
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
	/* dml21_prepare_mcache_programming: each of a plane's n pipes (DC's
	 * order: its first slice, then its ODM or MPC slices) with the
	 * viewports SPL gives that pipe (dml21_get_pipe_mcache_config). The
	 * plane's source is its viewport at the surface origin, its destination
	 * the whole stream (rect_out_width, rect_out_height_spans_vactive);
	 * an ODM slice is resource_get_odm_slice_src_rect's (a 4:2:0 output's
	 * segments in whole pixel pairs, each after the first one pixel wider
	 * to the left). */
	static struct dml2_build_mcache_programming_in_out mc;
	mc.dml2_instance = init.dml2_instance;
	for (int k = 0; k < planes; k++) {
		struct dml2_plane_mcache_configuration_descriptor *d = &mc.mcache_configurations[k];
		const struct dml2_plane_parameters *p = &prog.display_config.plane_descriptors[k];
		const struct dml2_timing_cfg *t = &cfg.stream_descriptors[p->stream_index].timing;
		unsigned int n = prog.plane_programming[k].num_dpps_required;
		int odms = prog.stream_programming[p->stream_index].num_odms_required;
		bool fmt420 = cfg.stream_descriptors[p->stream_index].output.output_format == dml2_420;
		int video = p->pixel_format == dml2_420_8 ? 1 : p->pixel_format == dml2_420_10 ? 2 : 0;
		int w = (int)t->h_active, h = (int)t->v_active;

		d->plane_descriptor = p;
		d->mcache_allocation = &prog.plane_programming[k].mcache_allocation;
		d->num_pipes = (char)n;
		for (unsigned int j = 0; j < n; j++) {
			struct dml2_pipe_configuration_descriptor *c = &d->pipe_configurations[j];
			int odm_x = 0, odm_w = w, mpc_index = 0, mpc_count = 1;
			int vp[4], vp_c[4];

			if (odms > 1) {
				int first = w / odms;

				if ((first % 2) && fmt420)
					first++;
				odm_x = first * (int)j;
				odm_w = (int)j + 1 == odms ? w - first * (odms - 1) : first;
				if (j > 0 && fmt420) {
					odm_x -= 1;
					odm_w += 1;
				}
			} else {
				mpc_index = (int)j;
				mpc_count = (int)n;
			}
			narf_spl_viewports((int)p->composition.viewport.plane0.width,
					   (int)p->composition.viewport.plane0.height, w, h, w, h,
					   odm_x, odm_w, mpc_index, mpc_count,
					   (int)p->composition.rotation_angle, video, vp, vp_c);
			c->plane0.viewport_x_start = vp[0];
			c->plane0.viewport_width = vp[2];
			c->plane1.viewport_x_start = vp_c[0];
			c->plane1.viewport_width = vp_c[2];
			c->plane1_enabled = p->pixel_format == dml2_420_8 || p->pixel_format == dml2_420_10;
		}
		mc.num_configurations++;
	}
	bool mcache_ok = dml2_build_mcache_programming(&mc);
	printf("PLAN");
	for (int k = 0; k < planes; k++) {
		const struct dml2_dchub_per_pipe_register_set *r = prog.plane_programming[k].pipe_regs[0];
		const union dml2_global_sync_programming *g =
			&prog.stream_programming[cfg.plane_descriptors[k].stream_index].global_sync;
		const struct dml2_dchub_watermark_regs *w = &prog.global_regs.wm_regs[0];
		const struct dml2_display_arb_regs *ar = &prog.global_regs.arb_regs;
		const struct dml2_display_dlg_regs *d = &r->dlg_regs;
		const struct dml2_display_ttu_regs *u = &r->ttu_regs;
#define RQ(p) r->rq_regs.p.chunk_size, r->rq_regs.p.min_chunk_size, r->rq_regs.p.meta_chunk_size, \
	r->rq_regs.p.min_meta_chunk_size, r->rq_regs.p.dpte_group_size, r->rq_regs.p.mpte_group_size, \
	r->rq_regs.p.swath_height, r->rq_regs.p.pte_row_height_linear
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
			d->refcyc_per_line_delivery_pre_c, d->refcyc_per_line_delivery_c,
			u->refcyc_per_req_delivery_pre_c, u->refcyc_per_req_delivery_c,
			RQ(rq_regs_l), RQ(rq_regs_c),
			r->rq_regs.drq_expansion_mode, r->rq_regs.prq_expansion_mode,
			r->rq_regs.mrq_expansion_mode, r->rq_regs.crq_expansion_mode,
			r->rq_regs.plane1_base_address, r->rq_regs.unbounded_request_enabled,
			ar->allow_sdpif_rate_limit_when_cstate_req,
		};
		if (k)
			printf(" |");
		for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++)
			printf(" %lu", v[i]);
		/* The mcache allocation: counts, boundaries, global ids, sharing;
		 * then four pipes' main mcache registers (MALL must equal them). */
		const struct dml2_mcache_surface_allocation *a = &prog.plane_programming[k].mcache_allocation;
		printf(" %u %u", a->num_mcaches_plane0, a->num_mcaches_plane1);
		for (int i = 0; i < DML2_MAX_MCACHES + 1; i++)
			printf(" %d", a->mcache_x_offsets_plane0[i]);
		for (int i = 0; i < DML2_MAX_MCACHES + 1; i++)
			printf(" %d", a->mcache_x_offsets_plane1[i]);
		for (int i = 0; i < DML2_MAX_MCACHES + 1; i++)
			printf(" %d", a->global_mcache_ids_plane0[i]);
		for (int i = 0; i < DML2_MAX_MCACHES + 1; i++)
			printf(" %d", a->global_mcache_ids_plane1[i]);
		printf(" %d", a->last_slice_sharing.plane0_plane1);
		for (int j = 0; j < 4; j++) {
			const struct dml2_hubp_pipe_mcache_regs *x = mc.per_plane_pipe_mcache_regs[k][j];

			if (!mcache_ok || !x) {
				printf(" 0 0 0 0 0 0");
				continue;
			}
			if (memcmp(&x->main, &x->mall, sizeof(x->main)))
				printf(" MALLDIFF");
			printf(" %u %u %u %u %u %u", x->main.p0.mcache_id_first, x->main.p0.mcache_id_second,
			       x->main.p0.split_location, x->main.p1.mcache_id_first,
			       x->main.p1.mcache_id_second, x->main.p1.split_location);
		}
		print_odm_pipes(&prog.plane_programming[k]);
	}
	putchar('\n');
	return 0;
}
