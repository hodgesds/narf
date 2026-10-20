/* Host stand-in for DC's resource.h: the DSC count. */
#ifndef NARF_DSC_RESOURCE_H
#define NARF_DSC_RESOURCE_H
struct resource_caps {
	int num_dsc;
};
struct display_stream_compressor;
struct resource_pool {
	const struct resource_caps *res_cap;
	struct display_stream_compressor *dscs[6];
};
#endif
