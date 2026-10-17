/* Host stand-in. */
#include <linux/types.h>
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define BUILD_BUG_ON(c) _Static_assert(!(c), #c)
#define WARN_ON_ONCE(c) (c)
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
