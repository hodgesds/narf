/* DCN401 pipe acquisition as Linux DC runs it, replayed over a fake pool
 * and resource contexts. Host-only; check.sh compiles it after shim.h and
 * the functions it cuts out of the Linux tree.
 *
 * The script (stdin) is a sequence of DC transactions as amdgpu_dm builds
 * them in dm_atomic_check: the new context starts as a copy of the current
 * one (dc_state_create_copy), planes and streams are removed and added
 * (dc_state_remove_plane, dc_state_remove_stream, dc_state_add_stream,
 * dc_state_add_plane), DML21's pipe counts are mapped onto it
 * (map_dc_pipes_with_callbacks), and a commit makes it the current state.
 * One operation per line:
 *   pool <CC_DC_PIPE_DIS>   a new board: the pool keeps the unfused pipes
 *                           (pipe_count; see tests/rdna4_family), both
 *                           states empty
 *   begin                   new = a copy of current
 *   +stream <s>             dc_state_add_stream (the OTG master)
 *   -stream <s>             dc_state_remove_stream
 *   +plane <s> <p>          dc_state_add_plane on stream s
 *   -plane <s> <p>          dc_state_remove_plane
 *   map <s>:<odm>:<m,m..>.. map_dc_pipes_with_callbacks with DML's ODM count
 *                           for each stream and MPC count for each of its
 *                           planes (stream_status order)
 *   commit                  current = new
 * Output echoes each line; operations end in " ok" or " fail" (their
 * result) and a commit is followed by the current pipes, one field per
 * pool pipe: "-" for a cleared pipe_ctx, else s<stream>, then p<plane>,
 * t<top>, b<bottom>, l<prev ODM> and r<next ODM> for those set. Stream
 * and plane ids are the script's; no stream uses DSC.
 *
 * Linux's resource_add_otg_master_for_stream_output calls the pool's
 * add_stream_to_ctx (dcn30 -> dcn20_add_stream_to_ctx ->
 * resource_map_pool_resources), of which only the OTG master acquisition
 * and its DC_NO_CONTROLLER_RESOURCE check are pipe acquisition: that is
 * add_stream_to_ctx below. resource_remove_otg_master_for_stream_output
 * releases encoders, audio and clock sources before clearing the OTG
 * master's pipe_ctx; only the clearing is kept.
 */

static int targets_odm[256];
static int targets_mpc[256][MAX_SURFACES];
static bool targeted[256];

static unsigned int get_target_odm_factor(const struct dml2_context *ctx,
		struct dc_state *state, const struct dml_display_cfg_st *disp_cfg,
		struct dml2_dml_to_dc_pipe_mapping *mapping, const struct dc_stream_state *stream)
{
	(void)ctx;
	(void)state;
	(void)disp_cfg;
	(void)mapping;
	return targeted[stream->stream_id] ? (unsigned int)targets_odm[stream->stream_id] : 1;
}

static unsigned int get_target_mpc_factor(struct dml2_context *ctx, struct dc_state *state,
		const struct dml_display_cfg_st *disp_cfg,
		struct dml2_dml_to_dc_pipe_mapping *mapping, const struct dc_stream_status *status,
		const struct dc_stream_state *stream, int plane_idx)
{
	(void)ctx;
	(void)state;
	(void)disp_cfg;
	(void)mapping;
	(void)status;
	return targeted[stream->stream_id] ? (unsigned int)targets_mpc[stream->stream_id][plane_idx]
					   : 1;
}

static enum dc_status add_stream_to_ctx(struct dc *dc, struct dc_state *new_ctx,
		struct dc_stream_state *stream)
{
	struct pipe_ctx *pipe_ctx;

	acquire_otg_master_pipe_for_stream(dc->current_state, new_ctx, dc->res_pool, stream);
	pipe_ctx = resource_get_otg_master_for_stream(&new_ctx->res_ctx, stream);
	if (!pipe_ctx || pipe_ctx->stream_res.tg == NULL)
		return DC_NO_CONTROLLER_RESOURCE;
	return DC_OK;
}

void resource_remove_otg_master_for_stream_output(struct dc_state *context,
		const struct resource_pool *pool, struct dc_stream_state *stream)
{
	struct pipe_ctx *otg_master = resource_get_otg_master_for_stream(
			&context->res_ctx, stream);

	(void)pool;
	if (!otg_master)
		return;
	memset(otg_master, 0, sizeof(*otg_master));
}

static struct timing_generator tgs[MAX_PIPES];
static struct mem_input mis[MAX_PIPES];
static struct hubp hubps[MAX_PIPES];
static struct input_pixel_processor ipps[MAX_PIPES];
static struct transform xfms[MAX_PIPES];
static struct dpp dpps[MAX_PIPES];
static struct output_pixel_processor opps[MAX_PIPES];
static struct display_stream_compressor dscs[MAX_PIPES];
static const struct resource_caps caps = { .num_opp = 4, .num_dsc = 4 };
static const struct resource_funcs funcs = {
	.acquire_free_pipe_as_secondary_dpp_pipe = dcn32_acquire_free_pipe_as_secondary_dpp_pipe,
	.acquire_free_pipe_as_secondary_opp_head = dcn32_acquire_free_pipe_as_secondary_opp_head,
	.release_pipe = dcn20_release_pipe,
	.add_stream_to_ctx = add_stream_to_ctx,
};
static struct resource_pool pool;
static struct logger logger;
static struct dc the_dc;
static struct dc_context dc_ctx = { .dc = &the_dc, .logger = &logger };
static struct dc_state current, next;
static struct dc_stream_state streams[256];
static struct dc_plane_state planes[256];

/* dc_state_copy_internal: the pipe links point into the copy. */
static void copy_state(struct dc_state *dst, const struct dc_state *src)
{
	memcpy(dst, src, sizeof(*dst));
	for (int i = 0; i < MAX_PIPES; i++) {
		struct pipe_ctx *p = &dst->res_ctx.pipe_ctx[i];

		if (p->top_pipe)
			p->top_pipe = &dst->res_ctx.pipe_ctx[p->top_pipe->pipe_idx];
		if (p->bottom_pipe)
			p->bottom_pipe = &dst->res_ctx.pipe_ctx[p->bottom_pipe->pipe_idx];
		if (p->prev_odm_pipe)
			p->prev_odm_pipe = &dst->res_ctx.pipe_ctx[p->prev_odm_pipe->pipe_idx];
		if (p->next_odm_pipe)
			p->next_odm_pipe = &dst->res_ctx.pipe_ctx[p->next_odm_pipe->pipe_idx];
	}
}

static void dump(const struct dc_state *s)
{
	static const struct pipe_ctx zero;

	printf("commit");
	for (unsigned int i = 0; i < pool.pipe_count; i++) {
		const struct pipe_ctx *p = &s->res_ctx.pipe_ctx[i];

		if (!memcmp(p, &zero, sizeof(zero))) {
			printf(" -");
			continue;
		}
		printf(" s%d", p->stream ? (int)p->stream->stream_id : -1);
		if (p->plane_state)
			printf("p%d", p->plane_state->id);
		if (p->top_pipe)
			printf("t%d", p->top_pipe->pipe_idx);
		if (p->bottom_pipe)
			printf("b%d", p->bottom_pipe->pipe_idx);
		if (p->prev_odm_pipe)
			printf("l%d", p->prev_odm_pipe->pipe_idx);
		if (p->next_odm_pipe)
			printf("r%d", p->next_odm_pipe->pipe_idx);
	}
	printf("\n");
}

static void new_pool(unsigned int fuses)
{
	memset(&pool, 0, sizeof(pool));
	pool.pipe_count = 4 - (unsigned int)__builtin_popcount(fuses & 0xf);
	pool.timing_generator_count = pool.pipe_count;
	pool.res_cap = &caps;
	pool.funcs = &funcs;
	for (unsigned int j = 0; j < pool.pipe_count; j++) {
		pool.timing_generators[j] = &tgs[j];
		pool.mis[j] = &mis[j];
		pool.hubps[j] = &hubps[j];
		pool.ipps[j] = &ipps[j];
		pool.transforms[j] = &xfms[j];
		pool.dpps[j] = &dpps[j];
		pool.opps[j] = &opps[j];
		pool.dscs[j] = &dscs[j];
	}
	memset(&current, 0, sizeof(current));
	memset(&next, 0, sizeof(next));
	the_dc.ctx = &dc_ctx;
	the_dc.current_state = &current;
	the_dc.res_pool = &pool;
	the_dc.config.enable_windowed_mpo_odm = true;
	for (int i = 0; i < 256; i++) {
		streams[i].ctx = &dc_ctx;
		streams[i].stream_id = (uint32_t)i;
		planes[i].id = i;
	}
}

static bool map(char *args)
{
	struct dml2_context ctx;
	struct dml_display_cfg_st cfg;
	struct dml2_dml_to_dc_pipe_mapping mapping;

	memset(targeted, 0, sizeof(targeted));
	for (char *tok = strtok(args, " \n"); tok; tok = strtok(NULL, " \n")) {
		int s = atoi(tok);
		char *odm = strchr(tok, ':');
		char *mpc = odm ? strchr(odm + 1, ':') : NULL;

		if (!mpc)
			return false;
		targeted[s] = true;
		targets_odm[s] = atoi(odm + 1);
		for (int k = 0; k < MAX_SURFACES; k++)
			targets_mpc[s][k] = 1;
		for (int k = 0; mpc && k < MAX_SURFACES; k++) {
			targets_mpc[s][k] = atoi(mpc + 1);
			mpc = strchr(mpc + 1, ',');
		}
	}
	memset(&ctx, 0, sizeof(ctx));
	ctx.config.callbacks.dc = &the_dc;
	ctx.config.callbacks.update_pipes_for_stream_with_slice_count =
			resource_update_pipes_for_stream_with_slice_count;
	ctx.config.callbacks.update_pipes_for_plane_with_slice_count =
			resource_update_pipes_for_plane_with_slice_count;
	ctx.config.callbacks.get_mpc_slice_count = resource_get_mpc_slice_count;
	ctx.config.callbacks.get_odm_slice_count = resource_get_odm_slice_count;
	ctx.config.callbacks.get_otg_master_for_stream = resource_get_otg_master_for_stream;
	ctx.config.callbacks.get_dpp_pipes_for_plane = resource_get_dpp_pipes_for_plane;
	return map_dc_pipes_with_callbacks(&ctx, &next, &cfg, &mapping, &current);
}

int main(void)
{
	char line[512];

	while (fgets(line, sizeof(line), stdin)) {
		char op[16] = "";
		unsigned int a = 0, b = 0;
		bool ok;

		line[strcspn(line, "\n")] = 0;
		if (line[0] == '#' || line[0] == 0) {
			printf("%s\n", line);
			continue;
		}
		sscanf(line, "%15s %u %u", op, &a, &b);
		if (!strcmp(op, "pool")) {
			sscanf(line, "pool %x", &a);
			new_pool(a);
			printf("%s\n", line);
			continue;
		}
		if (!strcmp(op, "begin")) {
			copy_state(&next, &current);
			printf("%s\n", line);
			continue;
		}
		if (!strcmp(op, "commit")) {
			copy_state(&current, &next);
			dump(&current);
			continue;
		}
		if (!strcmp(op, "+stream"))
			ok = dc_state_add_stream(&the_dc, &next, &streams[a]) == DC_OK;
		else if (!strcmp(op, "-stream"))
			ok = dc_state_remove_stream(&the_dc, &next, &streams[a]) == DC_OK;
		else if (!strcmp(op, "+plane"))
			ok = dc_state_add_plane(&the_dc, &streams[a], &planes[b], &next);
		else if (!strcmp(op, "-plane"))
			ok = dc_state_remove_plane(&the_dc, &streams[a], &planes[b], &next);
		else if (!strcmp(op, "map")) {
			char args[512];

			strcpy(args, line + 4);
			ok = map(args);
		} else {
			fprintf(stderr, "unknown operation: %s\n", line);
			return 1;
		}
		printf("%s %s\n", line, ok ? "ok" : "fail");
	}
	return 0;
}
