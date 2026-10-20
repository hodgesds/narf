/* amdgpu_dm's DP SST depth search (amdgpu_dm_create_validate_stream_for_sink)
 * with Linux's DSC decision for DCN401, compiled on the host. Each stdin line:
 *   <DPCD 0x060-0x06F as 32 hex digits> <max_dispclk_khz> <pix_clk_100hz>
 *   <h_active> <h_total> <v_active> <v_total> <edid_bpc 0|6..16>
 *   <max_requested_bpc> <lanes 1|2|4>
 *   <link_rate: DPCD 8b/10b code 6/10/20/30 (with FEC) or 128b/132b
 *    1000/1350/2000 (UHBR10/13.5/20, 10 Mbps units)>
 * prints the first depth that validates,
 *   <bpc> -                                                uncompressed
 *   <bpc> <slices_h> <slices_v> <bpp_x16> <dsc_kbps>      compressed
 * or FAIL. The bpc mask is the function's: bpc_order {16, 12, 10, 8, 6}
 * above neither max_requested_bpc nor display_info.bpc; each stream is
 * built at amdgpu_dm_convert_color_depth_from_display_info's depth for
 * that bpc, in RGB (a DP sink: no YCbCr 4:4:4, no YCbCr 4:2:2 or 4:2:0
 * requested), apply_dsc_policy_for_stream compresses it for a dongle-less
 * DP sink at the link's bandwidth (dc_dsc_compute_config, harness.c's
 * DCN401 encoder) and dc_validate_stream's dp_validate_mode_timing takes
 * it when dc_bandwidth_in_kbps_from_timing fits dp_link_bandwidth_kbps of
 * that (maximum) link. 6 bpc is skipped: the native encoders take 8, 10
 * and 12 bpc only. */
#include "dc_dsc.h"
#include "dsc.h"
#include "dc.h"
#include "clk_mgr.h"
#include "resource.h"
#include "dcn401_dsc.c"
#include <stdlib.h>

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

/* dp_link_bandwidth_kbps (link_validation.c) of the link, with FEC on
 * 8b/10b. */
static uint32_t link_kbps(unsigned int lanes, unsigned int rate)
{
	if (rate >= 1000)
		return rate * 10000 * lanes / 10000 * 9641;
	return rate * 27000 * 10 * lanes / 10000 * (8000 / 100 * 97);
}

/* amdgpu_dm_convert_color_depth_from_display_info for RGB. */
static enum dc_color_depth color_depth(unsigned int info_bpc, unsigned int requested)
{
	unsigned int bpc = info_bpc ? info_bpc : 8;

	if (requested > 0) {
		bpc = bpc < requested ? bpc : requested;
		bpc -= bpc & 1;
	}
	switch (bpc) {
	case 0: return COLOR_DEPTH_888;
	case 6: return COLOR_DEPTH_666;
	case 8: return COLOR_DEPTH_888;
	case 10: return COLOR_DEPTH_101010;
	case 12: return COLOR_DEPTH_121212;
	case 14: return COLOR_DEPTH_141414;
	case 16: return COLOR_DEPTH_161616;
	default: return COLOR_DEPTH_UNDEFINED;
	}
}

static unsigned int depth_bpc(enum dc_color_depth d)
{
	switch (d) {
	case COLOR_DEPTH_666: return 6;
	case COLOR_DEPTH_888: return 8;
	case COLOR_DEPTH_101010: return 10;
	case COLOR_DEPTH_121212: return 12;
	case COLOR_DEPTH_141414: return 14;
	case COLOR_DEPTH_161616: return 16;
	default: return 0;
	}
}

int main(void)
{
	static const struct clk_mgr_funcs clk_funcs = { .get_max_clock_khz = max_clock_khz };
	static const struct resource_caps res_cap = { .num_dsc = 4 };
	static const unsigned int bpc_order[] = { 16, 12, 10, 8, 6 };
	struct clk_mgr clk = { .funcs = &clk_funcs };
	struct resource_pool pool = { .res_cap = &res_cap };
	struct dc dc = { .caps = { .max_odm_combine_factor = 4 }, .clk_mgr = &clk, .res_pool = &pool };
	struct dc_context ctx = { .dc = &dc };
	struct dcn401_dsc dsc401 = { 0 };
	char hex[64];
	unsigned int pix, ha, ht, va, vt, info_bpc, requested, lanes, rate;

	dsc401.base.ctx = &ctx;
	dsc401.base.funcs = &dcn401_dsc_funcs;
	dsc401.max_image_width = 5184;
	while (scanf("%63s %u %u %u %u %u %u %u %u %u %u", hex, &max_dispclk_khz, &pix, &ha,
		     &ht, &va, &vt, &info_bpc, &requested, &lanes, &rate) == 11) {
		uint8_t dpcd[16] = { 0 }, branch[3] = { 0 };
		struct dsc_dec_dpcd_caps caps = { 0 };
		enum dc_link_encoding_format format =
			rate >= 1000 ? DC_LINK_ENCODING_DP_128b_132b : DC_LINK_ENCODING_DP_8b_10b;
		uint32_t max_bw = link_kbps(lanes, rate);
		bool parsed;
		unsigned int j;
		int i;

		for (i = 0; i < 16; i++)
			sscanf(hex + 2 * i, "%2hhx", &dpcd[i]);
		parsed = dc_dsc_parse_dsc_dpcd(&dc, dpcd, branch, &caps);
		for (j = 0; j < sizeof(bpc_order) / sizeof(bpc_order[0]); j++) {
			unsigned int bpc = bpc_order[j];
			struct dc_dsc_config_options options;
			struct dc_crtc_timing t = { 0 };

			if (requested > 0 && bpc > requested)
				continue;
			if (info_bpc && bpc > info_bpc)
				continue;
			if (bpc == 6)
				continue;
			t.pix_clk_100hz = pix;
			t.h_addressable = ha;
			t.h_total = ht;
			t.v_addressable = va;
			t.v_total = vt;
			t.pixel_encoding = PIXEL_ENCODING_RGB;
			t.display_color_depth = color_depth(info_bpc, bpc);
			if (depth_bpc(t.display_color_depth) < 8)
				continue;
			dc_dsc_get_default_config_option(&dc, &options);
			if (parsed && dc_dsc_compute_config(&dsc401.base, &caps, &options, max_bw, &t,
							     format, &t.dsc_cfg))
				t.flags.DSC = 1;
			if (dc_bandwidth_in_kbps_from_timing(&t, format) > max_bw)
				continue;
			if (!t.flags.DSC)
				printf("%u -\n", depth_bpc(t.display_color_depth));
			else
				printf("%u %u %u %u %u\n", depth_bpc(t.display_color_depth),
				       t.dsc_cfg.num_slices_h, t.dsc_cfg.num_slices_v,
				       t.dsc_cfg.bits_per_pixel,
				       dc_dsc_stream_bandwidth_in_kbps(&t, t.dsc_cfg.bits_per_pixel,
								       t.dsc_cfg.num_slices_h,
								       t.dsc_cfg.is_dp));
			break;
		}
		if (j == sizeof(bpc_order) / sizeof(bpc_order[0]))
			printf("FAIL\n");
	}
	return 0;
}
