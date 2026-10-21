/* DCN401 pipe harvesting as Linux builds its resource pool. Host-only.
 *
 * check.sh cuts these pieces out of the Linux tree into $work and compiles
 * this file with -I$work:
 *   res_cap.inc     res_cap_dcn4_01 (dcn401_resource.c)
 *   fuses.inc       read_pipe_fuses's mask and dcn401_resource_construct's
 *                   num_pipes count, from "max number of pipes" to the
 *                   pool's pipe/TG/MPCC counts
 *   pipes.inc       the construct loop creating HUBPs, DPPs, OPPs, TGs and
 *                   ABMs into packed slots ("HUBPs, DPPs" to "PSR")
 *   mpc.inc         the MPC creation line (its MPCC count)
 *   dscs.inc        the DSC creation loop
 *   max_streams.inc dc_create's max_streams (dc.c)
 *   acquire_dsc.inc dcn20_acquire_dsc (dcn20_resource.c)
 * For every CC_DC_PIPE_DIS value 0..15 it prints one line:
 *   <fuses> pipes=<n> mpccs=<n> streams=<n> hubp=<i,...> dpp=<...>
 *   opp=<...> tg=<...> abm=<...> mpcc=<...> dsc=<...>
 * each list by pool slot (pipe index): the instance Linux addresses, mpcc
 * the slot's plane_res.mpcc_inst (dpps[j]->inst) and dsc the DSC
 * dcn20_acquire_dsc gives that pipe index. The kernel test
 * rdna4_pipe_pool_matches_linux_harvesting holds amdgpu_rdna4::PipePool
 * to pipe_pool.txt.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_PIPES 6
#define ASSERT(x) ((void)(x))
#define BREAK_TO_DEBUGGER() ((void)0)
#define dm_error(...) ((void)0)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define CC_DC_PIPE_DIS__DC_FULL_DIS_MASK 0x00000100U
#define NO_UNDERLAY_PIPE ((unsigned int)-1)

struct resource_caps {
	int num_timing_generator, num_opp, num_video_plane, num_audio,
		num_stream_encoder, num_hpo_frl, num_hpo_dp_stream_encoder,
		num_hpo_dp_link_encoder, num_pll, num_dwb, num_ddc, num_vmid,
		num_mpc_3dlut, num_dsc;
};
struct block { int inst; };
struct hubp { int inst; };
struct dpp { int inst; };
struct output_pixel_processor { int inst; };
struct timing_generator { int inst; };
struct abm { int inst; };
struct display_stream_compressor { int inst; };
struct mpc { int num_mpcc; };
struct resource_pool {
	const struct resource_caps *res_cap;

	unsigned int underlay_pipe_index, timing_generator_count, pipe_count,
		mpcc_count, stream_enc_count;
	struct hubp *hubps[MAX_PIPES];
	struct dpp *dpps[MAX_PIPES];
	struct output_pixel_processor *opps[MAX_PIPES];
	struct timing_generator *timing_generators[MAX_PIPES];
	struct abm *multiple_abms[MAX_PIPES];
	struct display_stream_compressor *dscs[MAX_PIPES];
	struct mpc *mpc;
};
struct dcn401_resource_pool { struct resource_pool base; };
struct stream_resource { struct display_stream_compressor *dsc; };
struct pipe_ctx { struct stream_resource stream_res; };
struct resource_context {
	struct pipe_ctx pipe_ctx[MAX_PIPES];
	bool is_dsc_acquired[MAX_PIPES];
};
struct dc_state { struct resource_context res_ctx; };
struct dc_caps { unsigned int max_streams; };
struct dc {
	const struct resource_pool *res_pool;
	struct dc_state *current_state;
	struct dc_caps caps;
};
struct dc_context { uint32_t cc_dc_pipe_dis; };

static struct hubp hubp_inst[MAX_PIPES];
static struct dpp dpp_inst[MAX_PIPES];
static struct output_pixel_processor opp_inst[MAX_PIPES];
static struct timing_generator tg_inst[MAX_PIPES];
static struct abm abm_inst[MAX_PIPES];
static struct display_stream_compressor dsc_inst[MAX_PIPES];
static struct mpc the_mpc;
static int abm_regs[MAX_PIPES], abm_shift, abm_mask;

#define REG_READ(r) (ctx->cc_dc_pipe_dis)
#define CREATE(arr, i) (arr[i].inst = (int)(i), &arr[i])
#define dcn401_hubp_create(ctx, i) CREATE(hubp_inst, i)
#define dcn401_dpp_create(ctx, i) CREATE(dpp_inst, i)
#define dcn401_opp_create(ctx, i) CREATE(opp_inst, i)
#define dcn401_timing_generator_create(ctx, i) CREATE(tg_inst, i)
#define dcn401_dsc_create(ctx, i) CREATE(dsc_inst, i)
#define dmub_abm_create(ctx, regs, shift, mask) \
	(abm_inst[(regs) - abm_regs].inst = (int)((regs) - abm_regs), \
	 (void)(shift), (void)(mask), &abm_inst[(regs) - abm_regs])
#define dcn401_mpc_create(ctx, n, luts) \
	((void)(luts), the_mpc.num_mpcc = (int)(n), &the_mpc)

static const struct resource_caps res_cap_dcn4_01 =
#include "res_cap.inc"
;

static uint32_t read_pipe_fuses(struct dc_context *ctx)
{
#include "fuses_read.inc"
}

static bool construct(struct dc_context *ctx, struct dcn401_resource_pool *pool)
{
	int i, j;
	uint32_t pipe_fuses = 0;
	uint32_t num_pipes = 4;

	pool->base.res_cap = &res_cap_dcn4_01;
#include "fuses.inc"
#include "pipes.inc"
#include "mpc.inc"
#include "dscs.inc"
	(void)j;
	return true;
create_fail:
	return false;
}

#include "acquire_dsc.inc"

static void list(const char *name, struct dcn401_resource_pool *pool,
		 int (*inst)(const struct resource_pool *, unsigned int))
{
	printf(" %s=", name);
	for (unsigned int j = 0; j < pool->base.pipe_count; j++)
		printf("%s%d", j ? "," : "", inst(&pool->base, j));
}
static int hubp_of(const struct resource_pool *p, unsigned int j) { return p->hubps[j]->inst; }
static int dpp_of(const struct resource_pool *p, unsigned int j) { return p->dpps[j]->inst; }
static int opp_of(const struct resource_pool *p, unsigned int j) { return p->opps[j]->inst; }
static int tg_of(const struct resource_pool *p, unsigned int j) { return p->timing_generators[j]->inst; }
static int abm_of(const struct resource_pool *p, unsigned int j) { return p->multiple_abms[j]->inst; }
/* resource_map_pool_resources / dcn32_acquire_free_pipe_as_secondary_*:
 * plane_res.mpcc_inst = pool->dpps[pipe_idx]->inst. */
static int mpcc_of(const struct resource_pool *p, unsigned int j) { return p->dpps[j]->inst; }

static struct dc_state current_state;
static struct dc_state new_state;
static struct dcn401_resource_pool *dsc_pool;
static int dsc_of(const struct resource_pool *p, unsigned int j)
{
	struct dc dc = { .res_pool = p, .current_state = &current_state };
	struct display_stream_compressor *dsc = NULL;

	(void)dsc_pool;
	memset(&new_state, 0, sizeof(new_state));
	dcn20_acquire_dsc(&dc, &new_state.res_ctx, &dsc, (int)j);
	return dsc ? dsc->inst : -1;
}

int main(void)
{
	for (uint32_t fuses = 0; fuses < 16; fuses++) {
		struct dc_context ctx = { .cc_dc_pipe_dis = fuses };
		struct dcn401_resource_pool pool;
		struct dc dc_obj;
		struct dc *dc = &dc_obj;

		memset(&pool, 0, sizeof(pool));
		memset(&dc_obj, 0, sizeof(dc_obj));
		if (!construct(&ctx, &pool))
			return 1;
		pool.base.stream_enc_count = (unsigned int)res_cap_dcn4_01.num_stream_encoder;
		dc->res_pool = &pool.base;
		{
			unsigned int full_pipe_count;
#include "max_streams.inc"
		}
		dsc_pool = &pool;
		printf("%#x pipes=%u mpccs=%d streams=%u", fuses, pool.base.pipe_count,
		       pool.base.mpc->num_mpcc, dc->caps.max_streams);
		list("hubp", &pool, hubp_of);
		list("dpp", &pool, dpp_of);
		list("opp", &pool, opp_of);
		list("tg", &pool, tg_of);
		list("abm", &pool, abm_of);
		list("mpcc", &pool, mpcc_of);
		list("dsc", &pool, dsc_of);
		printf("\n");
	}
	return 0;
}
