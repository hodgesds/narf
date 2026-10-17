/* Host stand-in: only the DPCD register names. */
#include <linux/types.h>
#define BIT(n) (1UL << (n))
#define GENMASK(h, l) (((~0UL) << (l)) & (~0UL >> (sizeof(long) * 8 - 1 - (h))))
#include <drm/display/drm_dp.h>
