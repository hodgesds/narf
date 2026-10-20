/* Host stand-in for DC's os_types.h, pre-included under Linux's own guard
 * so DC's copy (found first by quote includes) compiles to nothing. */
#ifndef _OS_TYPES_H_
#define _OS_TYPES_H_
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#define ASSERT(x) ((void)0)
#define BREAK_TO_DEBUGGER() ((void)0)
#define BUILD_BUG_ON(c) ((void)sizeof(char[1 - 2 * !!(c)]))
#define DC_LOG_ERROR(...) ((void)0)
#define DC_LOG_WARNING(...) ((void)0)
#define LOG_GAMMA_WRITE(...) ((void)0)
#define div64_u64_rem(a, b, r) (*(r) = (a) % (b), (a) / (b))
#define div64_s64(a, b) ((int64_t)(a) / (int64_t)(b))
#define div_u64(a, b) ((uint64_t)(a) / (uint32_t)(b))
#define ilog2(n) (31 - __builtin_clz(n))
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
/* color_gamma.c allocates with kvzalloc_obj(s) and frees with kvfree. */
#define kvzalloc_obj(x) calloc(1, sizeof(x))
#define kvzalloc_objs(x, n) calloc((n), sizeof(x))
#define kvfree(p) free(p)
struct kref { int refcount; };
struct dc_context;
struct dal_logger;
#endif
