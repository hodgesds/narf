/* Linux's MST DSC fairness search (amdgpu_dm_mst_types.c), compiled on the
 * host with DCN401's DSC encoder as harness.c has it. check.sh extracts
 * get_fec_overhead_multiplier, kbps_to_peak_pbn,
 * set_dsc_configs_from_fairness_vars, bpp_x16_from_pbn, increase_dsc_bpp and
 * try_disable_dsc from the Linux source into mst_fair.c, included below
 * with the DRM types they read. The DRM atomic helpers they call are
 * modelled: drm_dp_atomic_find_time_slots records each port's PBN and its
 * DIV_ROUND_UP(dfixed_const(pbn), pbn_div) slots; drm_dp_mst_atomic_check
 * accepts when every stream's slots fit the link's and its PBN its port's,
 * and the streams sharing the upstream hop fit that hop's PBN. The steps of
 * compute_mst_dsc_configs_for_link are replayed around them.
 *
 * Each stdin line:
 *   <encoding 0=8b/10b 1=128b/132b> <link_kbps> <link slots 63|64>
 *   <max_dispclk_khz> <shared hop PBN> <streams n>, then per stream
 *   <DPCD 0x060-0x06F as 32 hex digits, or - for no decoder>
 *   <pix_clk_100hz> <h_active> <h_total> <v_active> <v_total> <port PBN>
 * prints "FAIL" or, per stream, "<pbn> <dsc 0|1> <bpp_x16> <slices_h>
 * <slices_v>" separated by " |". */
#include "dc_dsc.h"
#include "dsc.h"
#include "dc.h"
#include "clk_mgr.h"
#include "resource.h"
#include "dcn401_dsc.c"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

void dc_assert_fp_enabled(void) {}
void dc_fpu_begin(const char *f, const int l) { (void)f; (void)l; }
void dc_fpu_end(const char *f, const int l) { (void)f; (void)l; }
uint32_t dm_read_reg_func(const struct dc_context *c, uint32_t a, const char *f)
{ (void)c; (void)a; (void)f; abort(); }
void dm_write_reg_func(const struct dc_context *c, uint32_t a, uint32_t v, const char *f)
{ (void)c; (void)a; (void)v; (void)f; abort(); }
uint32_t generic_reg_set_ex(const struct dc_context *c, uint32_t a, uint32_t v, int n,
		uint8_t s, uint32_t m, uint32_t f, ...)
{ (void)c; (void)a; (void)v; (void)n; (void)s; (void)m; (void)f; abort(); }
uint32_t generic_reg_update_ex(const struct dc_context *c, uint32_t a, int n,
		uint8_t s, uint32_t m, uint32_t f, ...)
{ (void)c; (void)a; (void)n; (void)s; (void)m; (void)f; abort(); }
void generic_reg_wait(const struct dc_context *c, uint32_t a, uint32_t m, uint32_t s,
	uint32_t v, unsigned int d, unsigned int t, const char *f, int l)
{ (void)c; (void)a; (void)m; (void)s; (void)v; (void)d; (void)t; (void)f; (void)l; abort(); }

static unsigned int max_dispclk_khz;

static unsigned int max_clock_khz(struct clk_mgr *m, enum clk_type t)
{
	(void)m;
	return t == CLK_TYPE_DSCCLK ? max_dispclk_khz / 3 : max_dispclk_khz;
}

/* The DC and DRM sides the extracted functions read. */
#ifndef ENOSPC
#define ENOSPC 28
#endif
struct dc_sink_dsc_caps {
	struct dsc_dec_dpcd_caps dsc_dec_caps;
};
struct dc_sink {
	enum signal_type sink_signal;
	struct dc_edid_caps edid_caps;
	struct dc_sink_dsc_caps dsc_caps;
	struct dc_context *ctx;
};
typedef struct { uint32_t full; } fixed20_12;
#define dfixed_const(A) (uint32_t)(((A) << 12))
#define dfixed_trunc(A) ((A).full >> 12)
struct drm_display_info { int max_dsc_bpp; };
struct drm_connector { struct drm_display_info display_info; };
struct amdgpu_dm_connector { struct drm_connector base; struct dc_link *dc_link; };
struct drm_dp_mst_topology_mgr { int unused; };
struct drm_dp_mst_port { struct drm_dp_mst_topology_mgr *mgr; int index; };
struct drm_atomic_commit { int unused; };
struct drm_dp_mst_topology_state { fixed20_12 pbn_div; };
enum dsc_clock_force_state {
	DSC_CLK_FORCE_DEFAULT = 0,
	DSC_CLK_FORCE_ENABLE,
	DSC_CLK_FORCE_DISABLE,
};
struct dsc_mst_fairness_vars {
	int pbn;
	bool dsc_enabled;
	int bpp_x16;
	struct amdgpu_dm_connector *aconnector;
};
#define DRM_DEBUG_DRIVER(...) ((void)0)
#define PBN_FEC_OVERHEAD_MULTIPLIER_8B_10B 1031
#define PBN_FEC_OVERHEAD_MULTIPLIER_128B_132B 1000
#define DIV64_U64_ROUND_UP(a, b) (((a) + (b) - 1) / (b))
#ifndef div_u64
#define div_u64(a, b) ((a) / (b))
#endif
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(a, b) (((a) + (b) - 1) / (b))
#endif
#ifndef MAX_PIPES
#define MAX_PIPES 6
#endif

static enum dc_link_encoding_format encoding;
static struct drm_dp_mst_topology_state mst_state;
static int link_slots, shared_pbn, nstreams;
static int port_pbn[MAX_PIPES], port_limit[MAX_PIPES], port_slots[MAX_PIPES];

enum dc_link_encoding_format dc_link_get_highest_encoding_format(const struct dc_link *l)
{
	(void)l;
	return encoding;
}
enum dp_link_encoding dc_link_dp_mst_decide_link_encoding_format(const struct dc_link *l)
{
	(void)l;
	return encoding == DC_LINK_ENCODING_DP_128b_132b ? DP_128b_132b_ENCODING :
		DP_8b_10b_ENCODING;
}
int drm_dp_atomic_find_time_slots(struct drm_atomic_commit *s,
		struct drm_dp_mst_topology_mgr *m, struct drm_dp_mst_port *p, int pbn)
{
	(void)s;
	(void)m;
	port_pbn[p->index] = pbn;
	port_slots[p->index] = DIV_ROUND_UP(dfixed_const(pbn), mst_state.pbn_div.full);
	return port_slots[p->index];
}
int drm_dp_mst_atomic_check(struct drm_atomic_commit *s)
{
	int i, slots = 0, shared = 0;

	(void)s;
	for (i = 0; i < nstreams; i++) {
		if (port_pbn[i] > port_limit[i])
			return -ENOSPC;
		slots += port_slots[i];
		shared += port_pbn[i];
	}
	return slots <= link_slots && shared <= shared_pbn ? 0 : -ENOSPC;
}

#include "mst_fair.c"

int main(void)
{
	static const struct clk_mgr_funcs clk_funcs = { .get_max_clock_khz = max_clock_khz };
	static const struct resource_caps res_cap = { .num_dsc = 4 };
	static struct dcn401_dsc dsc401;
	struct clk_mgr clk = { .funcs = &clk_funcs };
	struct resource_pool pool = { .res_cap = &res_cap };
	struct dc dc = { .caps = { .max_odm_combine_factor = 4 }, .clk_mgr = &clk, .res_pool = &pool };
	struct dc_context ctx = { .dc = &dc };
	unsigned int enc, link_kbps, slots, dispclk, shared, n;

	dsc401.base.ctx = &ctx;
	dsc401.base.funcs = &dcn401_dsc_funcs;
	dsc401.max_image_width = 5184;
	pool.dscs[0] = &dsc401.base;
	while (scanf("%u %u %u %u %u %u", &enc, &link_kbps, &slots, &dispclk, &shared, &n) == 6) {
		static struct dc_sink sinks[MAX_PIPES];
		static struct dc_crtc_timing timings[MAX_PIPES];
		static struct amdgpu_dm_connector connectors[MAX_PIPES];
		static struct drm_dp_mst_port ports[MAX_PIPES];
		static struct drm_dp_mst_topology_mgr mgr;
		struct dsc_mst_fairness_params params[MAX_PIPES];
		struct dsc_mst_fairness_vars vars[MAX_PIPES];
		struct drm_atomic_commit state;
		uint16_t fec;
		unsigned int i;
		int ret, k = 0, count = n;

		memset(params, 0, sizeof(params));
		memset(vars, 0, sizeof(vars));
		memset(sinks, 0, sizeof(sinks));
		memset(timings, 0, sizeof(timings));
		encoding = enc ? DC_LINK_ENCODING_DP_128b_132b : DC_LINK_ENCODING_DP_8b_10b;
		max_dispclk_khz = dispclk;
		link_slots = slots;
		shared_pbn = shared;
		nstreams = n;
		/* dm_mst_get_pbn_divider. */
		mst_state.pbn_div.full = dfixed_const((uint32_t)((uint64_t)link_kbps * 100 / (8 * 1000 * 54))) / 100;
		for (i = 0; i < n; i++) {
			char hex[64];
			uint8_t dpcd[16] = { 0 }, branch[3] = { 0 };
			struct dc_crtc_timing *t = &timings[i];
			struct dc_dsc_policy policy = { 0 };
			int j;

			if (scanf("%63s %u %u %u %u %u %d", hex, &t->pix_clk_100hz, &t->h_addressable,
				  &t->h_total, &t->v_addressable, &t->v_total, &port_limit[i]) != 7)
				return 2;
			t->display_color_depth = COLOR_DEPTH_888;
			t->pixel_encoding = PIXEL_ENCODING_RGB;
			sinks[i].ctx = &ctx;
			if (hex[0] != '-') {
				for (j = 0; j < 16; j++)
					sscanf(hex + 2 * j, "%2hhx", &dpcd[j]);
				dc_dsc_parse_dsc_dpcd(&dc, dpcd, branch, &sinks[i].dsc_caps.dsc_dec_caps);
			}
			ports[i].mgr = &mgr;
			ports[i].index = i;
			params[i].timing = t;
			params[i].sink = &sinks[i];
			params[i].aconnector = &connectors[i];
			params[i].port = &ports[i];
			params[i].compression_possible = sinks[i].dsc_caps.dsc_dec_caps.is_dsc_supported;
			dc_dsc_get_policy_for_timing(t, 0, &policy, encoding);
			if (!dc_dsc_compute_bandwidth_range(&dsc401.base, 0, policy.min_target_bpp * 16,
					policy.max_target_bpp * 16, &sinks[i].dsc_caps.dsc_dec_caps, t,
					encoding, &params[i].bw_range))
				params[i].bw_range.stream_kbps = dc_bandwidth_in_kbps_from_timing(t, encoding);
		}
		/* compute_mst_dsc_configs_for_link from "Try no compression". */
		fec = get_fec_overhead_multiplier(NULL);
		for (i = 0; i < n; i++) {
			vars[i + k].aconnector = params[i].aconnector;
			vars[i + k].pbn = kbps_to_peak_pbn(params[i].bw_range.stream_kbps, fec);
			vars[i + k].dsc_enabled = false;
			vars[i + k].bpp_x16 = 0;
			drm_dp_atomic_find_time_slots(&state, params[i].port->mgr, params[i].port,
						      vars[i + k].pbn);
		}
		ret = drm_dp_mst_atomic_check(&state);
		if (ret != 0) {
			for (i = 0; i < n; i++) {
				if (params[i].compression_possible &&
				    params[i].clock_force_enable != DSC_CLK_FORCE_DISABLE) {
					vars[i + k].pbn = kbps_to_peak_pbn(params[i].bw_range.min_kbps, fec);
					vars[i + k].dsc_enabled = true;
					vars[i + k].bpp_x16 = params[i].bw_range.min_target_bpp_x16;
				} else {
					vars[i + k].pbn = kbps_to_peak_pbn(params[i].bw_range.stream_kbps, fec);
					vars[i + k].dsc_enabled = false;
					vars[i + k].bpp_x16 = 0;
				}
				drm_dp_atomic_find_time_slots(&state, params[i].port->mgr,
							      params[i].port, vars[i + k].pbn);
			}
			if (drm_dp_mst_atomic_check(&state) != 0) {
				printf("FAIL\n");
				continue;
			}
			increase_dsc_bpp(&state, &mst_state, NULL, params, vars, count, k);
			try_disable_dsc(&state, NULL, params, vars, count, k);
		}
		set_dsc_configs_from_fairness_vars(params, vars, count, k);
		for (i = 0; i < n; i++) {
			const struct dc_dsc_config *c = &timings[i].dsc_cfg;

			printf("%s%d %d %d %u %u", i ? " | " : "", vars[i].pbn, timings[i].flags.DSC,
			       timings[i].flags.DSC ? (int)c->bits_per_pixel : 0,
			       timings[i].flags.DSC ? c->num_slices_h : 0,
			       timings[i].flags.DSC ? c->num_slices_v : 0);
		}
		printf("\n");
	}
	return 0;
}
