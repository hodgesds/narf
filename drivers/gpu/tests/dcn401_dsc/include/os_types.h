/* Host stand-in for DC's os_types.h, pre-included under Linux's own guard
 * so DC's copy (found first by quote includes) compiles to nothing. */
#ifndef _OS_TYPES_H_
#define _OS_TYPES_H_
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/types.h>
#define CONFIG_DRM_AMD_DC_FP 1
#define LITTLEENDIAN_CPU
#define ASSERT(x) ((void)0)
#define ASSERT_CRITICAL(x) ((void)0)
#define BREAK_TO_DEBUGGER() ((void)0)
#define dm_output_to_console(...) ((void)0)
#define dm_error(...) ((void)0)
#define DRM_DEBUG_KMS(...) ((void)0)
#define DC_LOG_DSC(...) ((void)0)
#define DC_LOG_DC(...) ((void)0)
#define DC_LOGGER_INIT(x) ((void)0)
#define IS_ENABLED(x) 0
#define DC_FP_START() ((void)0)
#define DC_FP_END() ((void)0)
#define swap(a, b) do { __typeof__(a) __t = (a); (a) = (b); (b) = __t; } while (0)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) min(a, b)
#define MAX(a, b) max(a, b)
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define div_u64(a, b) ((uint64_t)(a) / (uint32_t)(b))
#define div64_u64_rem(a, b, r) (*(r) = (a) % (b), (a) / (b))
#define cpu_to_be16(x) __builtin_bswap16(x)
#define ERANGE 34
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define div64_s64(a, b) ((int64_t)(a) / (int64_t)(b))
#define div_s64(a, b) ((int64_t)(a) / (int32_t)(b))
#define div64_u64(a, b) ((uint64_t)(a) / (uint64_t)(b))
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
struct kref { int refcount; };
#endif
