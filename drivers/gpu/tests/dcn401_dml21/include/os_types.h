/* Host stand-in for DC's os_types.h: enough libc for DML21 to build. */
#ifndef NARF_DML21_OS_TYPES_H
#define NARF_DML21_OS_TYPES_H
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define noinline_for_stack __attribute__((noinline))
#define ASSERT(x) ((void)0)
#define BREAK_TO_DEBUGGER() ((void)0)
#define swap(a, b) do { __typeof__(a) __t = (a); (a) = (b); (b) = __t; } while (0)
#define dm_output_to_console(...) ((void)0)
#endif
