/* Host stand-in for DC's os_types.h: enough libc for the FRL capacity check. */
#ifndef NARF_FRL_OS_TYPES_H
#define NARF_FRL_OS_TYPES_H
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define ASSERT(x) ((void)0)
#define __maybe_unused __attribute__((unused))
#define dc_assert_fp_enabled() ((void)0)
#endif
