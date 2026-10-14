/* Host stand-in for DC's dc.h: the members dc_dsc.c reads. */
#ifndef NARF_DSC_DC_H
#define NARF_DSC_DC_H
#include "dc_types.h"
struct clk_mgr;
struct resource_pool;
struct dc_caps {
	uint32_t max_odm_combine_factor;
};
struct dc_debug_options {
	bool disable_dsc;
	uint32_t dsc_bpp_increment_div;
	uint32_t dsc_min_slice_height_override;
	int force_odm_combine;
};
struct dc {
	struct dc_caps caps;
	struct dc_debug_options debug;
	struct clk_mgr *clk_mgr;
	struct resource_pool *res_pool;
};
uint32_t dc_bandwidth_in_kbps_from_timing(const struct dc_crtc_timing *timing,
	const enum dc_link_encoding_format link_encoding);
#endif
