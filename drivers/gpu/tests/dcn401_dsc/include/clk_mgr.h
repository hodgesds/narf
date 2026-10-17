/* Host stand-in for DC's clk_mgr.h: get_max_clock_khz only. */
#ifndef NARF_DSC_CLK_MGR_H
#define NARF_DSC_CLK_MGR_H
enum clk_type {
	CLK_TYPE_DCFCLK,
	CLK_TYPE_FCLK,
	CLK_TYPE_MCLK,
	CLK_TYPE_SOCCLK,
	CLK_TYPE_DTBCLK,
	CLK_TYPE_DISPCLK,
	CLK_TYPE_DPPCLK,
	CLK_TYPE_DSCCLK,
	CLK_TYPE_COUNT
};
struct clk_mgr;
struct clk_mgr_funcs {
	unsigned int (*get_max_clock_khz)(struct clk_mgr *clk_mgr, enum clk_type clk_type);
};
struct clk_mgr {
	const struct clk_mgr_funcs *funcs;
};
#endif
