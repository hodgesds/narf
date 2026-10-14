/* Host stand-in for DC's resource.h: the DSC count. */
#ifndef NARF_DSC_RESOURCE_H
#define NARF_DSC_RESOURCE_H
struct resource_caps {
	int num_dsc;
};
struct resource_pool {
	const struct resource_caps *res_cap;
};
#endif
