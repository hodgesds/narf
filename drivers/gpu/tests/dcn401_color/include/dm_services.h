/* Host stand-in for DC's dm_services.h: register writes land in
 * harness.c's generic_reg_set_ex, which records them. */
#ifndef NARF_COLOR_DM_SERVICES_H
#define NARF_COLOR_DM_SERVICES_H
#include "os_types.h"
#include "include/fixed31_32.h"
#include "dc_hw_types.h"
uint32_t generic_reg_set_ex(const struct dc_context *ctx,
		uint32_t addr, uint32_t reg_val, int n,
		uint8_t shift1, uint32_t mask1, uint32_t field_value1, ...);
uint32_t generic_reg_update_ex(const struct dc_context *ctx,
		uint32_t addr, int n,
		uint8_t shift1, uint32_t mask1, uint32_t field_value1, ...);
uint32_t dm_read_reg_func(const struct dc_context *ctx, uint32_t address,
		const char *func_name);
void dm_write_reg_func(const struct dc_context *ctx, uint32_t address,
		uint32_t value, const char *func_name);
#define dm_read_reg(ctx, address) dm_read_reg_func(ctx, address, __func__)
#define dm_write_reg(ctx, address, value) \
	dm_write_reg_func(ctx, address, value, __func__)
void generic_reg_wait(const struct dc_context *ctx,
	uint32_t addr, uint32_t mask, uint32_t shift, uint32_t condition_value,
	unsigned int delay_between_poll_us, unsigned int time_out_num_tries,
	const char *func_name, int line);
#endif
