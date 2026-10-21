/* Drives Linux's dc_dmub_srv_rb_based_fams2_update_config (extracted
 * verbatim by check.sh, after shim.h) with DCN401's DC debug defaults
 * (dcn401_resource.c: fams2_config enable, enable_offload_flip and
 * enable_stall_recovery; no visual confirm) and prints the command list it
 * posts. One line per case:
 *   <enable> <max_allow_delay_us> <lock_wait_time_us> <num_streams>
 *   <features.all> <recovery_timeout_us> <hwfq_flip_programming_delay_us>
 *   <max_allow_to_target_delta_us>
 *   then per stream: <type> <otg_vline_time_ns> <htotal> <vtotal>
 *   <vblank_start> <vblank_end> <max_vtotal> <allow_start_otg_vline>
 *   <allow_end_otg_vline> <drr_keepout_otg_vline>
 *   <scheduling_delay_otg_vlines> <contention_delay_otg_vlines>
 *   <vline_int_ack_delay_otg_vlines> <allow_to_target_delay_otg_vlines>
 *   <config.all> <otg_inst> <pipe_mask> <num_planes> <plane_pipe_masks x6>
 *   <legacy.vactive_det_fill_delay_otg_vlines>
 *   = <64-byte command in hex>...
 * amdgpu_dmub_navi48.rs's fams2_config_commands must emit those bytes. */

static uint32_t seed = 0x6d2b79f5u;
static uint32_t rnd(uint32_t n)
{
	seed = seed * 1664525u + 1013904223u;
	return (seed >> 8) % n;
}
static uint32_t rnd32(void)
{
	return rnd(1u << 16) << 16 | rnd(1u << 16);
}

bool dm_execute_dmub_cmd_list(const struct dc_context *ctx, unsigned int count,
			      union dmub_rb_cmd *cmd, enum dm_dmub_wait_type wait_type)
{
	(void)ctx;
	(void)wait_type;
	printf(" =");
	for (unsigned int i = 0; i < count; i++) {
		const uint8_t *b = (const uint8_t *)&cmd[i].fams2_config;
		printf(" ");
		for (unsigned int k = 0; k < sizeof(cmd[i].fams2_config); k++)
			printf("%02x", b[k]);
	}
	printf("\n");
	return true;
}

static void run(bool enable, const uint32_t g[7], unsigned int streams,
		const struct dmub_fams2_cmd_stream_static_base_state *base,
		const uint16_t *fill)
{
	struct dc_context ctx = { 0 };
	struct dc dc = { .ctx = &ctx };
	static struct dc_state context;
	unsigned int i, k;

	memset(&context, 0, sizeof(context));
	dc.debug.visual_confirm = VISUAL_CONFIRM_DISABLE;
	dc.debug.fams2_config.bits.enable = 1;
	dc.debug.fams2_config.bits.enable_offload_flip = 1;
	dc.debug.fams2_config.bits.enable_stall_recovery = 1;
	struct dmub_cmd_fams2_global_config *gc = &context.bw_ctx.bw.dcn.fams2_global_config;
	gc->max_allow_delay_us = g[0];
	gc->lock_wait_time_us = g[1];
	gc->num_streams = g[2];
	gc->features.all = g[3];
	gc->recovery_timeout_us = g[4];
	gc->hwfq_flip_programming_delay_us = g[5];
	gc->max_allow_to_target_delta_us = g[6];
	for (i = 0; i < streams; i++) {
		context.bw_ctx.bw.dcn.fams2_stream_base_params[i].stream_v1.base = base[i];
		context.bw_ctx.bw.dcn.fams2_stream_sub_params[i].stream_v1.sub_state.legacy
			.vactive_det_fill_delay_otg_vlines = fill[i];
	}
	printf("%d %u %u %u %u %u %u %u", enable, g[0], g[1], g[2], g[3], g[4], g[5], g[6]);
	for (i = 0; i < streams; i++) {
		const struct dmub_fams2_cmd_stream_static_base_state *b = &base[i];
		printf(" %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u", b->type,
		       b->otg_vline_time_ns, b->htotal, b->vtotal, b->vblank_start, b->vblank_end,
		       b->max_vtotal, b->allow_start_otg_vline, b->allow_end_otg_vline,
		       b->drr_keepout_otg_vline, b->scheduling_delay_otg_vlines,
		       b->contention_delay_otg_vlines, b->vline_int_ack_delay_otg_vlines,
		       b->allow_to_target_delay_otg_vlines, b->config.all, b->otg_inst,
		       b->pipe_mask, b->num_planes);
		for (k = 0; k < DMUB_MAX_PLANES; k++)
			printf(" %u", b->plane_pipe_masks[k]);
		printf(" %u", fill[i]);
	}
	dc_dmub_srv_rb_based_fams2_update_config(&dc, &context, enable);
}

static struct dmub_fams2_cmd_stream_static_base_state stream(uint32_t type)
{
	struct dmub_fams2_cmd_stream_static_base_state b;

	memset(&b, 0, sizeof(b));
	b.type = type;
	b.otg_vline_time_ns = 14814;
	b.htotal = 2200;
	b.vtotal = 1125;
	b.vblank_start = 1121;
	b.vblank_end = 41;
	b.max_vtotal = 1125;
	b.allow_start_otg_vline = 1092;
	b.allow_end_otg_vline = 1094;
	b.drr_keepout_otg_vline = 1118;
	b.scheduling_delay_otg_vlines = 38;
	b.contention_delay_otg_vlines = 17;
	b.vline_int_ack_delay_otg_vlines = 3;
	b.allow_to_target_delay_otg_vlines = 5;
	b.config.bits.clamp_vtotal_min = 1;
	b.config.bits.min_ttu_vblank_usable = 1;
	b.otg_inst = 2;
	b.pipe_mask = 0x6;
	b.num_planes = 1;
	b.plane_pipe_masks[0] = 0x6;
	return b;
}

int main(void)
{
	struct dmub_fams2_cmd_stream_static_base_state base[MAX_STREAMS];
	uint16_t fill[MAX_STREAMS] = { 27, 0, 9, 0, 0, 0 };
	/* DC's FAMS2 features: enable, stall recovery, offload flip and the
	 * allow-delay check from the start. */
	uint32_t on = 1 | 1 << 2 | 1 << 4 | 1 << 6;
	uint32_t g[7] = { 100000, 5000, 0, on, 5000, 300, 0 };
	unsigned int i, k, n;

	base[0] = stream(FAMS2_STREAM_TYPE_VACTIVE);
	base[1] = stream(FAMS2_STREAM_TYPE_VBLANK);
	base[1].config.bits.is_drr = 1;
	base[1].otg_inst = 0;
	base[1].pipe_mask = 0x1;
	base[1].plane_pipe_masks[0] = 0x1;
	base[2] = stream(FAMS2_STREAM_TYPE_DRR);
	base[2].num_planes = 2;
	base[2].plane_pipe_masks[1] = 0x8;
	base[2].pipe_mask = 0xe;
	/* The hardware-exclusive methods' disable, with and without a
	 * configuration DC would have sent. */
	run(false, (uint32_t[7]){ 0 }, 0, base, fill);
	g[2] = 2;
	run(false, g, 2, base, fill);
	/* Enabled: none, one, two and three streams. */
	for (n = 0; n <= 3; n++) {
		g[2] = n;
		run(true, g, n, base, fill);
	}
	/* A configuration that needs no FAMS2 (enable clear, the legacy
	 * method without FAMS2) and one whose static features differ from
	 * DC's debug defaults (debug on, stall recovery and offload flip off,
	 * the PPT check and visual confirm asked for). */
	g[2] = 1;
	g[3] = 1 << 8;
	run(true, g, 1, base, fill);
	g[3] = 1 | 1 << 1 | 1 << 3 | 1 << 5 | 2 << 6;
	run(true, g, 1, base, fill);
	/* Every field over its range. */
	for (i = 0; i < 40; i++) {
		bool enable = rnd(4) != 0;

		n = rnd(MAX_STREAMS + 1);
		for (k = 0; k < 7; k++)
			g[k] = rnd32();
		g[2] = n;
		g[3] = rnd(1u << 9);
		for (k = 0; k < n; k++) {
			struct dmub_fams2_cmd_stream_static_base_state *b = &base[k];

			memset(b, 0, sizeof(*b));
			b->type = 1 + rnd(4);
			b->otg_vline_time_ns = rnd32();
			b->htotal = rnd(1u << 16);
			b->vtotal = rnd(1u << 16);
			b->vblank_start = rnd(1u << 16);
			b->vblank_end = rnd(1u << 16);
			b->max_vtotal = rnd(1u << 16);
			b->allow_start_otg_vline = rnd(1u << 16);
			b->allow_end_otg_vline = rnd(1u << 16);
			b->drr_keepout_otg_vline = rnd(1u << 16);
			b->scheduling_delay_otg_vlines = rnd(1u << 16);
			b->contention_delay_otg_vlines = rnd(1u << 16);
			b->vline_int_ack_delay_otg_vlines = rnd(1u << 16);
			b->allow_to_target_delay_otg_vlines = rnd(1u << 16);
			b->config.all = rnd(8);
			b->otg_inst = rnd(4);
			b->pipe_mask = rnd(16);
			b->num_planes = rnd(DMUB_MAX_PLANES + 1);
			for (unsigned int p = 0; p < DMUB_MAX_PLANES; p++)
				b->plane_pipe_masks[p] = rnd(16);
			fill[k] = rnd(1u << 16);
		}
		run(enable, g, n, base, fill);
	}
	return 0;
}
