/* Host shim for the Linux DML: the few dm_services.h names it uses. */
#ifndef NAVI22_DML30_SHIM_DM_SERVICES_H
#define NAVI22_DML30_SHIM_DM_SERVICES_H
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define ASSERT(x) ((void)(x))
#define BREAK_TO_DEBUGGER() ((void)0)
#define dc_assert_fp_enabled() ((void)0)
#define noinline_for_stack __attribute__((noinline))
#define DC_LOG_DML(...) ((void)0)
#endif
