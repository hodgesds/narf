/* Linux's DSC decision and configuration for DCN401, compiled on the host.
 * Each stdin line:
 *   <DPCD 0x060-0x06F as 32 hex digits> <max_dispclk_khz> <pix_clk_100hz>
 *   <h_active> <h_total> <v_active> <v_total> <bpc 8|10|12>
 *   <encoding 0=RGB 1=YCbCr444 2=YCbCr422 3=YCbCr420> <target_kbps>
 *   <link 0=8b/10b 1=128b/132b> <force 0|1>
 * prints
 *   <uncompressed kbps> -                                  no DSC
 *   <uncompressed kbps> <slices_h> <slices_v> <bpp_x16> <block_pred>
 *     <linebuf_depth> <version_minor> <dsc_kbps> <rc_buffer_model_size>
 *     <bytes_per_pixel> <slice_width> <is_444> <packed PPS, 128 bytes hex>
 * as amdgpu_dm's SST policy (apply_dsc_policy_for_stream, a DP sink with
 * no dongle) and link_set_dsc_on_stream/dsc2_get_packed_pps do it, with
 * DCN401's encoder (dsc401_get_single_enc_caps, four DSCs, ODM factor 4)
 * and DSCCLK at a third of the board's highest DISPCLK. */
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

int main(void)
{
	static const struct clk_mgr_funcs clk_funcs = { .get_max_clock_khz = max_clock_khz };
	static const struct resource_caps res_cap = { .num_dsc = 4 };
	struct clk_mgr clk = { .funcs = &clk_funcs };
	struct resource_pool pool = { .res_cap = &res_cap };
	struct dc dc = { .caps = { .max_odm_combine_factor = 4 }, .clk_mgr = &clk, .res_pool = &pool };
	struct dc_context ctx = { .dc = &dc };
	struct dcn401_dsc dsc401 = { 0 };
	char hex[64];
	unsigned int pix, ha, ht, va, vt, bpc, enc, target, link, force;

	dsc401.base.ctx = &ctx;
	dsc401.base.funcs = &dcn401_dsc_funcs;
	dsc401.max_image_width = 5184;
	while (scanf("%63s %u %u %u %u %u %u %u %u %u %u %u", hex, &max_dispclk_khz, &pix, &ha,
		     &ht, &va, &vt, &bpc, &enc, &target, &link, &force) == 12) {
		static const enum dc_pixel_encoding encodings[] = {
			PIXEL_ENCODING_RGB, PIXEL_ENCODING_YCBCR444,
			PIXEL_ENCODING_YCBCR422, PIXEL_ENCODING_YCBCR420,
		};
		uint8_t dpcd[16] = { 0 }, branch[3] = { 0 }, pps[128] = { 0 };
		struct dsc_dec_dpcd_caps caps = { 0 };
		struct dc_dsc_config_options options;
		struct dc_crtc_timing t = { 0 };
		struct dc_dsc_config cfg = { 0 };
		struct dsc_config dcfg = { 0 };
		struct dsc_reg_values regs = { 0 };
		struct dsc_optc_config optc = { 0 };
		enum dc_link_encoding_format format =
			link ? DC_LINK_ENCODING_DP_128b_132b : DC_LINK_ENCODING_DP_8b_10b;
		int i;

		for (i = 0; i < 16; i++)
			sscanf(hex + 2 * i, "%2hhx", &dpcd[i]);
		t.pix_clk_100hz = pix;
		t.h_addressable = ha;
		t.h_total = ht;
		t.v_addressable = va;
		t.v_total = vt;
		t.display_color_depth = bpc == 12 ? COLOR_DEPTH_121212 :
			bpc == 10 ? COLOR_DEPTH_101010 : COLOR_DEPTH_888;
		t.pixel_encoding = encodings[enc & 3];
		printf("%u", dc_bandwidth_in_kbps_from_timing(&t, format));
		dc_dsc_get_default_config_option(&dc, &options);
		options.force_dsc_when_not_needed = force;
		if (!dc_dsc_parse_dsc_dpcd(&dc, dpcd, branch, &caps) ||
		    !dc_dsc_compute_config(&dsc401.base, &caps, &options, target, &t, format, &cfg)) {
			printf(" -\n");
			continue;
		}
		dcfg.pic_width = ha;
		dcfg.pic_height = va;
		dcfg.pixel_encoding = t.pixel_encoding;
		dcfg.color_depth = t.display_color_depth;
		dcfg.dc_dsc_cfg = cfg;
		if (!dsc_prepare_config(&dcfg, &regs, &optc) ||
		    !dsc2_get_packed_pps(&dsc401.base, &dcfg, pps)) {
			printf(" ! prepare\n");
			continue;
		}
		printf(" %u %u %u %d %u %u %u %u %u %u %d ", cfg.num_slices_h, cfg.num_slices_v,
		       cfg.bits_per_pixel, cfg.block_pred_enable, cfg.linebuf_depth,
		       cfg.version_minor,
		       dc_dsc_stream_bandwidth_in_kbps(&t, cfg.bits_per_pixel, cfg.num_slices_h, cfg.is_dp),
		       regs.rc_buffer_model_size, optc.bytes_per_pixel, optc.slice_width,
		       optc.is_pixel_format_444);
		for (i = 0; i < 128; i++)
			printf("%02x", pps[i]);
		printf("\n");
	}
	return 0;
}
