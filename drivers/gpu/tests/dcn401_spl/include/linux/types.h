/* Host stand-in for <linux/types.h> and the kernel helpers SPL's
 * spl_os_types.h and spl_debug.h use. */
#ifndef NARF_SPL_LINUX_TYPES_H
#define NARF_SPL_LINUX_TYPES_H
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;
typedef int64_t s64;
/* An SPL assertion that fails is reported, not ignored: the vectors must
 * not depend on asserted-impossible paths. */
extern int narf_spl_warnings;
#define WARN_ON(x) ({ int __w = !!(x); if (__w) narf_spl_warnings++; __w; })
static inline uint64_t div_u64_rem(uint64_t a, uint32_t b, uint32_t *r)
{
	*r = a % b;
	return a / b;
}
static inline uint64_t div_u64(uint64_t a, uint32_t b) { return a / b; }
static inline uint64_t div64_u64(uint64_t a, uint64_t b) { return a / b; }
static inline uint64_t div64_u64_rem(uint64_t a, uint64_t b, uint64_t *r)
{
	*r = a % b;
	return a / b;
}
static inline int64_t div64_s64(int64_t a, int64_t b) { return a / b; }
#endif
