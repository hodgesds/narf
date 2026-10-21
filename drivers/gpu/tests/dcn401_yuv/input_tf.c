/* Linux reference for a DCN4 plane's input transfer function under the
 * CRTC's legacy gamma; see check.sh. Linked into color_input.c's binary
 * against Linux's own color_gamma.c, fixpt31_32.c, custom_float.c,
 * conversion.c and dcn30_cm_common.c, in tests/dcn401_color's host
 * environment.
 *
 * check.sh extracts, verbatim: map_crtc_degamma_to_dc_plane
 * (amdgpu_dm_color.c), dcn32_set_input_transfer_func (dcn32_hwseq.c),
 * dpp3_set_pre_degam (dcn30_dpp.c), and dpp3_enable_cm_block,
 * dpp30_get_gamcor_current, dpp3_program_gammcor_lut,
 * dpp3_power_on_gamcor_lut, dpp3_gamcor_reg_field,
 * dpp3_configure_gamcor_lut and dpp3_program_gamcor_lut (dcn30_dpp_cm.c).
 * Below are only the types they name, DCN 4.0.1's register offsets and
 * field masks (dcn_4_1_0), its dc debug options (dcn401_resource.c:
 * enable_mem_low_power.bits.cm = false) and dpp_funcs entries
 * (dcn401_dpp.c: no dpp_set_pregam_state), and a register file that
 * records every write.
 */
#include <errno.h>
#include <stdarg.h>
#include "dm_services.h"
#include "dc.h"
#include "opp.h"
#include "color_gamma.h"
#include "reg_helper.h"
#include "dcn30/dcn30_cm_common.h"
#include "asic_reg/dcn/dcn_4_1_0_offset.h"
#include "asic_reg/dcn/dcn_4_1_0_sh_mask.h"

/* --- The register file. --- */
static uint32_t regs[0x10000];
static uint32_t log_reg[4096], log_val[4096];
static int nlog;
/* CM_GAMCOR_CONTROL's MODE_CURRENT and SELECT_CURRENT read back what the
 * hardware latched, never what software writes. */
#define GAMCOR_RO (CM0_CM_GAMCOR_CONTROL__CM_GAMCOR_MODE_CURRENT_MASK | \
		   CM0_CM_GAMCOR_CONTROL__CM_GAMCOR_SELECT_CURRENT_MASK)
static uint32_t ro_mask(uint32_t addr)
{
	return addr == regCM0_CM_GAMCOR_CONTROL ? GAMCOR_RO : 0;
}
static void reg_write(uint32_t addr, uint32_t value)
{
	uint32_t ro = ro_mask(addr);

	regs[addr] = (regs[addr] & ro) | (value & ~ro);
	log_reg[nlog] = addr;
	log_val[nlog] = value & ~ro;
	nlog++;
}
static uint32_t fields(uint32_t reg_val, int n, uint8_t shift1, uint32_t mask1,
		       uint32_t value1, va_list ap)
{
	uint32_t mask = mask1, value = (value1 << shift1) & mask1;

	for (int i = 1; i < n; i++) {
		uint32_t shift = va_arg(ap, uint32_t);
		uint32_t m = va_arg(ap, uint32_t);
		uint32_t v = va_arg(ap, uint32_t);

		mask |= m;
		value |= (v << (uint8_t)shift) & m;
	}
	return (reg_val & ~mask) | value;
}
uint32_t generic_reg_set_ex(const struct dc_context *ctx, uint32_t addr,
		uint32_t reg_val, int n, uint8_t shift1, uint32_t mask1,
		uint32_t field_value1, ...)
{
	va_list ap;

	(void)ctx;
	va_start(ap, field_value1);
	reg_val = fields(reg_val, n, shift1, mask1, field_value1, ap);
	va_end(ap);
	reg_write(addr, reg_val);
	return reg_val;
}
uint32_t generic_reg_update_ex(const struct dc_context *ctx, uint32_t addr,
		int n, uint8_t shift1, uint32_t mask1, uint32_t field_value1, ...)
{
	va_list ap;
	uint32_t reg_val;

	(void)ctx;
	va_start(ap, field_value1);
	reg_val = fields(regs[addr], n, shift1, mask1, field_value1, ap);
	va_end(ap);
	reg_write(addr, reg_val);
	return reg_val;
}
uint32_t generic_reg_get(const struct dc_context *ctx, uint32_t addr,
		uint8_t shift, uint32_t mask, uint32_t *field_value)
{
	(void)ctx;
	*field_value = (regs[addr] & mask) >> shift;
	return regs[addr];
}
void generic_reg_wait(const struct dc_context *ctx, uint32_t addr, uint32_t mask,
		uint32_t shift, uint32_t condition_value,
		unsigned int delay_between_poll_us, unsigned int time_out_num_tries,
		const char *func_name, int line)
{
	(void)ctx; (void)addr; (void)mask; (void)shift; (void)condition_value;
	(void)delay_between_poll_us; (void)time_out_num_tries; (void)func_name; (void)line;
}

/* --- The DC types the extracted functions name. --- */
struct dc_debug_options {
	bool cm_in_bypass;
	union {
		struct { bool cm; } bits;
	} enable_mem_low_power;
};
struct dc {
	struct dc_debug_options debug;
	struct { bool ips_v2_support; } caps;
	bool optimized_required;
	struct resource_pool *res_pool;
	struct dce_hwseq *hwseq;
};
struct mpc { int unused; };
struct resource_pool { struct mpc *mpc; };
struct pipe_ctx;
struct dc_plane_state;
struct hwseq_private_funcs {
	bool (*set_mcm_luts)(struct pipe_ctx *pipe_ctx, const struct dc_plane_state *plane_state);
};
struct dce_hwseq { struct hwseq_private_funcs funcs; };
struct dpp;
struct dpp_funcs {
	bool (*dpp_program_gamcor_lut)(struct dpp *dpp_base, const struct pwl_params *params);
	void (*dpp_set_pre_degam)(struct dpp *dpp_base, enum dc_transfer_func_predefined tr);
	void (*dpp_set_pregam_state)(struct dpp *dpp_base, enum dc_transfer_func_predefined tr,
				     enum dc_scaling_linearity scaling);
};
struct dpp {
	const struct dpp_funcs *funcs;
	struct dc_context *ctx;
	struct pwl_params degamma_params;
	union {
		struct { bool disable_gamcor; } bits;
	} deferred_reg_writes;
};
struct output_pixel_processor { struct dc_context *ctx; };
struct pipe_ctx {
	struct { struct dpp *dpp; } plane_res;
	struct { struct output_pixel_processor *opp; } stream_res;
};
struct dc_plane_state {
	enum surface_pixel_format format;
	struct dc_transfer_func in_transfer_func;
	enum dc_scaling_linearity scaling_linearity;
};
struct drm_property_blob;
struct drm_color_lut;
struct dm_crtc_state {
	struct { struct drm_property_blob *degamma_lut; } base;
	bool cm_has_degamma;
	bool cm_is_degamma_srgb;
};
/* Only reached with a CRTC DEGAMMA_LUT, which amdgpu_dm does not expose on
 * DCN 4.0.1 (cm_has_degamma stays false). */
static const struct drm_color_lut *__extract_blob_lut(const struct drm_property_blob *blob,
						      uint32_t *size)
{
	(void)blob;
	*size = 0;
	return NULL;
}
static int __set_input_tf(struct dc_color_caps *caps, struct dc_transfer_func *func,
			  const struct drm_color_lut *lut, uint32_t lut_size)
{
	(void)caps; (void)func; (void)lut; (void)lut_size;
	abort();
}
#define MAX_COLOR_LUT_ENTRIES 4096

/* DCN 4.0.1's DPP register offsets and fields (dpp 0), as
 * dcn401_resource's tf_regs/tf_shift/tf_mask name them. */
#define DPP_REGS(X) \
	X(PRE_DEGAM, regCNVC_CFG0_PRE_DEGAM) \
	X(CM_CONTROL, regCM0_CM_CONTROL) \
	X(CM_MEM_PWR_CTRL, regCM0_CM_MEM_PWR_CTRL) \
	X(CM_MEM_PWR_STATUS, regCM0_CM_MEM_PWR_STATUS) \
	X(CM_GAMCOR_CONTROL, regCM0_CM_GAMCOR_CONTROL) \
	X(CM_GAMCOR_LUT_INDEX, regCM0_CM_GAMCOR_LUT_INDEX) \
	X(CM_GAMCOR_LUT_DATA, regCM0_CM_GAMCOR_LUT_DATA) \
	X(CM_GAMCOR_LUT_CONTROL, regCM0_CM_GAMCOR_LUT_CONTROL) \
	RAM(X, A) RAM(X, B)
#define RAM(X, r) \
	X(CM_GAMCOR_RAM##r##_START_CNTL_B, regCM0_CM_GAMCOR_RAM##r##_START_CNTL_B) \
	X(CM_GAMCOR_RAM##r##_START_CNTL_G, regCM0_CM_GAMCOR_RAM##r##_START_CNTL_G) \
	X(CM_GAMCOR_RAM##r##_START_CNTL_R, regCM0_CM_GAMCOR_RAM##r##_START_CNTL_R) \
	X(CM_GAMCOR_RAM##r##_START_SLOPE_CNTL_B, regCM0_CM_GAMCOR_RAM##r##_START_SLOPE_CNTL_B) \
	X(CM_GAMCOR_RAM##r##_START_SLOPE_CNTL_G, regCM0_CM_GAMCOR_RAM##r##_START_SLOPE_CNTL_G) \
	X(CM_GAMCOR_RAM##r##_START_SLOPE_CNTL_R, regCM0_CM_GAMCOR_RAM##r##_START_SLOPE_CNTL_R) \
	X(CM_GAMCOR_RAM##r##_START_BASE_CNTL_B, regCM0_CM_GAMCOR_RAM##r##_START_BASE_CNTL_B) \
	X(CM_GAMCOR_RAM##r##_START_BASE_CNTL_G, regCM0_CM_GAMCOR_RAM##r##_START_BASE_CNTL_G) \
	X(CM_GAMCOR_RAM##r##_START_BASE_CNTL_R, regCM0_CM_GAMCOR_RAM##r##_START_BASE_CNTL_R) \
	X(CM_GAMCOR_RAM##r##_END_CNTL1_B, regCM0_CM_GAMCOR_RAM##r##_END_CNTL1_B) \
	X(CM_GAMCOR_RAM##r##_END_CNTL2_B, regCM0_CM_GAMCOR_RAM##r##_END_CNTL2_B) \
	X(CM_GAMCOR_RAM##r##_END_CNTL1_G, regCM0_CM_GAMCOR_RAM##r##_END_CNTL1_G) \
	X(CM_GAMCOR_RAM##r##_END_CNTL2_G, regCM0_CM_GAMCOR_RAM##r##_END_CNTL2_G) \
	X(CM_GAMCOR_RAM##r##_END_CNTL1_R, regCM0_CM_GAMCOR_RAM##r##_END_CNTL1_R) \
	X(CM_GAMCOR_RAM##r##_END_CNTL2_R, regCM0_CM_GAMCOR_RAM##r##_END_CNTL2_R) \
	X(CM_GAMCOR_RAM##r##_OFFSET_B, regCM0_CM_GAMCOR_RAM##r##_OFFSET_B) \
	X(CM_GAMCOR_RAM##r##_OFFSET_G, regCM0_CM_GAMCOR_RAM##r##_OFFSET_G) \
	X(CM_GAMCOR_RAM##r##_OFFSET_R, regCM0_CM_GAMCOR_RAM##r##_OFFSET_R) \
	X(CM_GAMCOR_RAM##r##_REGION_0_1, regCM0_CM_GAMCOR_RAM##r##_REGION_0_1) \
	X(CM_GAMCOR_RAM##r##_REGION_32_33, regCM0_CM_GAMCOR_RAM##r##_REGION_32_33)
#define GAMCOR_RAMA CM0_CM_GAMCOR_RAMA_
#define DPP_FIELDS(X) \
	X(PRE_DEGAM_MODE, CNVC_CFG0_PRE_DEGAM__PRE_DEGAM_MODE) \
	X(PRE_DEGAM_SELECT, CNVC_CFG0_PRE_DEGAM__PRE_DEGAM_SELECT) \
	X(CM_BYPASS, CM0_CM_CONTROL__CM_BYPASS) \
	X(GAMCOR_MEM_PWR_FORCE, CM0_CM_MEM_PWR_CTRL__GAMCOR_MEM_PWR_FORCE) \
	X(GAMCOR_MEM_PWR_DIS, CM0_CM_MEM_PWR_CTRL__GAMCOR_MEM_PWR_DIS) \
	X(GAMCOR_MEM_PWR_STATE, CM0_CM_MEM_PWR_STATUS__GAMCOR_MEM_PWR_STATE) \
	X(CM_GAMCOR_MODE, CM0_CM_GAMCOR_CONTROL__CM_GAMCOR_MODE) \
	X(CM_GAMCOR_SELECT, CM0_CM_GAMCOR_CONTROL__CM_GAMCOR_SELECT) \
	X(CM_GAMCOR_MODE_CURRENT, CM0_CM_GAMCOR_CONTROL__CM_GAMCOR_MODE_CURRENT) \
	X(CM_GAMCOR_SELECT_CURRENT, CM0_CM_GAMCOR_CONTROL__CM_GAMCOR_SELECT_CURRENT) \
	X(CM_GAMCOR_LUT_INDEX, CM0_CM_GAMCOR_LUT_INDEX__CM_GAMCOR_LUT_INDEX) \
	X(CM_GAMCOR_LUT_DATA, CM0_CM_GAMCOR_LUT_DATA__CM_GAMCOR_LUT_DATA) \
	X(CM_GAMCOR_LUT_WRITE_COLOR_MASK, CM0_CM_GAMCOR_LUT_CONTROL__CM_GAMCOR_LUT_WRITE_COLOR_MASK) \
	X(CM_GAMCOR_LUT_HOST_SEL, CM0_CM_GAMCOR_LUT_CONTROL__CM_GAMCOR_LUT_HOST_SEL) \
	X(CM_GAMCOR_RAMA_EXP_REGION_START_B, CM0_CM_GAMCOR_RAMA_START_CNTL_B__CM_GAMCOR_RAMA_EXP_REGION_START_B) \
	X(CM_GAMCOR_RAMA_EXP_REGION_START_SEGMENT_B, CM0_CM_GAMCOR_RAMA_START_CNTL_B__CM_GAMCOR_RAMA_EXP_REGION_START_SEGMENT_B) \
	X(CM_GAMCOR_RAMA_EXP_REGION_START_SLOPE_B, CM0_CM_GAMCOR_RAMA_START_SLOPE_CNTL_B__CM_GAMCOR_RAMA_EXP_REGION_START_SLOPE_B) \
	X(CM_GAMCOR_RAMA_EXP_REGION_START_BASE_B, CM0_CM_GAMCOR_RAMA_START_BASE_CNTL_B__CM_GAMCOR_RAMA_EXP_REGION_START_BASE_B) \
	X(CM_GAMCOR_RAMA_EXP_REGION_END_BASE_B, CM0_CM_GAMCOR_RAMA_END_CNTL1_B__CM_GAMCOR_RAMA_EXP_REGION_END_BASE_B) \
	X(CM_GAMCOR_RAMA_EXP_REGION_END_B, CM0_CM_GAMCOR_RAMA_END_CNTL2_B__CM_GAMCOR_RAMA_EXP_REGION_END_B) \
	X(CM_GAMCOR_RAMA_EXP_REGION_END_SLOPE_B, CM0_CM_GAMCOR_RAMA_END_CNTL2_B__CM_GAMCOR_RAMA_EXP_REGION_END_SLOPE_B) \
	X(CM_GAMCOR_RAMA_OFFSET_B, CM0_CM_GAMCOR_RAMA_OFFSET_B__CM_GAMCOR_RAMA_OFFSET_B) \
	X(CM_GAMCOR_RAMA_EXP_REGION0_LUT_OFFSET, CM0_CM_GAMCOR_RAMA_REGION_0_1__CM_GAMCOR_RAMA_EXP_REGION0_LUT_OFFSET) \
	X(CM_GAMCOR_RAMA_EXP_REGION0_NUM_SEGMENTS, CM0_CM_GAMCOR_RAMA_REGION_0_1__CM_GAMCOR_RAMA_EXP_REGION0_NUM_SEGMENTS) \
	X(CM_GAMCOR_RAMA_EXP_REGION1_LUT_OFFSET, CM0_CM_GAMCOR_RAMA_REGION_0_1__CM_GAMCOR_RAMA_EXP_REGION1_LUT_OFFSET) \
	X(CM_GAMCOR_RAMA_EXP_REGION1_NUM_SEGMENTS, CM0_CM_GAMCOR_RAMA_REGION_0_1__CM_GAMCOR_RAMA_EXP_REGION1_NUM_SEGMENTS)
#define REG_FIELD(name, value) uint32_t name;
struct dcn3_dpp_registers { DPP_REGS(REG_FIELD) };
struct dcn3_dpp_shift { DPP_FIELDS(REG_FIELD) };
struct dcn3_dpp_mask { DPP_FIELDS(REG_FIELD) };
#define REG_INIT(name, value) .name = value,
#define SHIFT_INIT(name, f) .name = f##__SHIFT,
#define MASK_INIT(name, f) .name = f##_MASK,
static const struct dcn3_dpp_registers tf_regs = { DPP_REGS(REG_INIT) };
static const struct dcn3_dpp_shift tf_shift = { DPP_FIELDS(SHIFT_INIT) };
static const struct dcn3_dpp_mask tf_mask = { DPP_FIELDS(MASK_INIT) };
struct dcn3_dpp {
	struct dpp base;
	const struct dcn3_dpp_registers *tf_regs;
	const struct dcn3_dpp_shift *tf_shift;
	const struct dcn3_dpp_mask *tf_mask;
};
#define TO_DCN30_DPP(d) ((struct dcn3_dpp *)(d))

/* dcn30_dpp.c's and dcn30_dpp_cm.c's register access. */
#define REG(reg) dpp->tf_regs->reg
#define CTX dpp->base.ctx
#undef FN
#define FN(reg_name, field_name) dpp->tf_shift->field_name, dpp->tf_mask->field_name

#include "dpp_gamcor.inc"

/* dcn32_hwseq.c names its dc and hws through these. */
#include "set_input_tf.inc"

/* amdgpu_dm_color.c */
#include "map_degamma.inc"

static const struct dpp_funcs dcn401_dpp_funcs = {
	.dpp_program_gamcor_lut = dpp3_program_gamcor_lut,
	.dpp_set_pre_degam = dpp3_set_pre_degam,
};

/* What amdgpu_dm_update_plane_color_mgmt then dcn32_set_input_transfer_func
 * program on a plane in DC format `format`, on DPP 0 whose CM_GAMCOR_CONTROL
 * reads `gamcor_control` (its MODE/SELECT_CURRENT), under legacy gamma or
 * without (in_transfer_func bypassed). The register writes are left in
 * the log; returns nonzero when amdgpu_dm refuses (out of memory). */
int linux_input_tf(unsigned format, bool legacy, uint32_t gamcor_control)
{
	static bool once;
	static struct dc dc;
	static struct dc_context ctx;
	static struct resource_pool pool;
	static struct mpc mpc;
	static struct dce_hwseq hws;
	static struct dcn3_dpp dpp;
	static struct dc_plane_state plane;
	struct pipe_ctx pipe = { 0 };
	struct dm_crtc_state crtc = { .cm_is_degamma_srgb = legacy };
	/* dcn401_resource: dcn_arch 1, gamma_corr 1; DGAM ROM caps unused by
	 * the SDR transfer functions. */
	struct dc_color_caps caps = { .dpp = { .dcn_arch = 1, .gamma_corr = 1 } };

	if (!once) {
		setup_x_points_distribution();
		once = true;
	}
	pool.mpc = &mpc;
	dc.res_pool = &pool;
	dc.hwseq = &hws;
	ctx.dc = &dc;
	memset(&dpp, 0, sizeof(dpp));
	dpp.base.ctx = &ctx;
	dpp.base.funcs = &dcn401_dpp_funcs;
	dpp.tf_regs = &tf_regs;
	dpp.tf_shift = &tf_shift;
	dpp.tf_mask = &tf_mask;
	pipe.plane_res.dpp = &dpp.base;
	memset(&plane, 0, sizeof(plane));
	plane.format = format;
	memset(regs, 0, sizeof(regs));
	regs[regCM0_CM_GAMCOR_CONTROL] = gamcor_control;
	nlog = 0;
	/* amdgpu_dm_update_plane_color_mgmt with no plane color: bypass, or
	 * the CRTC's implicit degamma. */
	if (legacy) {
		if (map_crtc_degamma_to_dc_plane(&crtc, &plane, &caps))
			return 1;
	} else {
		plane.in_transfer_func.type = TF_TYPE_BYPASS;
		plane.in_transfer_func.tf = TRANSFER_FUNCTION_LINEAR;
	}
	dcn32_set_input_transfer_func(&dc, &pipe, &plane);
	return 0;
}
int linux_input_tf_writes(const uint32_t **reg, const uint32_t **val)
{
	*reg = log_reg;
	*val = log_val;
	return nlog;
}
/* PRE_DEGAM_MODE, PRE_DEGAM_SELECT, CM_GAMCOR_MODE and CM_GAMCOR_SELECT
 * as written, and FNV-1a 32 over the write log (each write as its dword
 * offset then its value, four little-endian bytes each). */
void linux_input_tf_result(uint32_t out[5])
{
	uint32_t h = 2166136261u;

	for (int i = 0; i < nlog; i++) {
		uint32_t w[2] = { log_reg[i], log_val[i] };

		for (int k = 0; k < 2; k++)
			for (int b = 0; b < 4; b++) {
				h ^= (w[k] >> (8 * b)) & 0xff;
				h *= 16777619u;
			}
	}
	out[0] = (regs[regCNVC_CFG0_PRE_DEGAM] & CNVC_CFG0_PRE_DEGAM__PRE_DEGAM_MODE_MASK) >>
		 CNVC_CFG0_PRE_DEGAM__PRE_DEGAM_MODE__SHIFT;
	out[1] = (regs[regCNVC_CFG0_PRE_DEGAM] & CNVC_CFG0_PRE_DEGAM__PRE_DEGAM_SELECT_MASK) >>
		 CNVC_CFG0_PRE_DEGAM__PRE_DEGAM_SELECT__SHIFT;
	out[2] = regs[regCM0_CM_GAMCOR_CONTROL] & CM0_CM_GAMCOR_CONTROL__CM_GAMCOR_MODE_MASK;
	out[3] = (regs[regCM0_CM_GAMCOR_CONTROL] & CM0_CM_GAMCOR_CONTROL__CM_GAMCOR_SELECT_MASK) >>
		 CM0_CM_GAMCOR_CONTROL__CM_GAMCOR_SELECT__SHIFT;
	out[4] = h;
}
