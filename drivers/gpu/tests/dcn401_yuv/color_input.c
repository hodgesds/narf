/* Linux reference for a DCN4 plane's input transfer function, input CSC
 * coefficient set and cursor color; see check.sh.
 *
 * check.sh extracts, verbatim: enum surface_pixel_format and enum
 * dc_color_space (dc_hw_types.h), enum dc_transfer_func_predefined (dc.h),
 * enum cursor_matrix_mode and enum dc_cursor_color_format (dc_hw_types.h),
 * enum dcn10_input_csc_select, dpp_input_csc_matrix (dc/inc/hw/dpp.h),
 * fill_dc_plane_info_and_addr's DRM-to-DC format switch and
 * fill_plane_color_attributes (amdgpu_dm.c), dpp401_dpp_setup's format
 * switch, map_crtc_degamma_to_dc_plane's implicit-degamma format switch
 * (amdgpu_dm_color.c), dpp3_set_pre_degam and dpp3_program_post_csc
 * (dcn30_dpp.c), dpp401_program_cursor_csc and dpp401_set_cursor_matrix
 * (dcn401_dpp_cm.c), dpp401_set_cursor_attributes, and the
 * ENABLE_CURSOR_DEGAMMA condition of amdgpu_dm_plane_handle_cursor_update
 * with dcn401_resource's dpp gamma_corr cap. The register macros below
 * record what those functions write.
 *
 * Input lines: <fourcc> <legacy gamma 0|1> <CM_POST_CSC_MODE_CURRENT>
 *   <COLOR_ENCODING> <COLOR_RANGE>
 * Output: "-" when amdgpu_dm refuses the plane, else PRE_DEGAM_MODE,
 *   PRE_DEGAM_SELECT, CM_POST_CSC_MODE, the coefficient set written ("A",
 *   "B" or "-" for bypass), CUR0_MATRIX_MODE and CUR0_ROM_EN.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define __maybe_unused
#define STATIC_IFN_KUNIT static
#define EXPORT_IF_KUNIT(x)
#define drm_err(...) ((void)0)
#define adev_to_drm(a) (a)
#define BREAK_TO_DEBUGGER() ((void)0)
#define DRM_FORMAT(a, b, c, d) ((uint32_t)(a) | (uint32_t)(b) << 8 | (uint32_t)(c) << 16 | (uint32_t)(d) << 24)
#define DRM_FORMAT_C8 DRM_FORMAT('C', '8', ' ', ' ')
#define DRM_FORMAT_RGB565 DRM_FORMAT('R', 'G', '1', '6')
#define DRM_FORMAT_XRGB8888 DRM_FORMAT('X', 'R', '2', '4')
#define DRM_FORMAT_ARGB8888 DRM_FORMAT('A', 'R', '2', '4')
#define DRM_FORMAT_XBGR8888 DRM_FORMAT('X', 'B', '2', '4')
#define DRM_FORMAT_ABGR8888 DRM_FORMAT('A', 'B', '2', '4')
#define DRM_FORMAT_XRGB2101010 DRM_FORMAT('X', 'R', '3', '0')
#define DRM_FORMAT_ARGB2101010 DRM_FORMAT('A', 'R', '3', '0')
#define DRM_FORMAT_XBGR2101010 DRM_FORMAT('X', 'B', '3', '0')
#define DRM_FORMAT_ABGR2101010 DRM_FORMAT('A', 'B', '3', '0')
#define DRM_FORMAT_NV21 DRM_FORMAT('N', 'V', '2', '1')
#define DRM_FORMAT_NV12 DRM_FORMAT('N', 'V', '1', '2')
#define DRM_FORMAT_P010 DRM_FORMAT('P', '0', '1', '0')
#define DRM_FORMAT_XRGB16161616F DRM_FORMAT('X', 'R', '4', 'H')
#define DRM_FORMAT_ARGB16161616F DRM_FORMAT('A', 'R', '4', 'H')
#define DRM_FORMAT_XBGR16161616F DRM_FORMAT('X', 'B', '4', 'H')
#define DRM_FORMAT_ABGR16161616F DRM_FORMAT('A', 'B', '4', 'H')
#define DRM_FORMAT_XRGB16161616 DRM_FORMAT('X', 'R', '4', '8')
#define DRM_FORMAT_ARGB16161616 DRM_FORMAT('A', 'R', '4', '8')
#define DRM_FORMAT_XBGR16161616 DRM_FORMAT('X', 'B', '4', '8')
#define DRM_FORMAT_ABGR16161616 DRM_FORMAT('A', 'B', '4', '8')

enum drm_color_encoding { DRM_COLOR_YCBCR_BT601, DRM_COLOR_YCBCR_BT709, DRM_COLOR_YCBCR_BT2020 };
enum drm_color_range { DRM_COLOR_YCBCR_LIMITED_RANGE, DRM_COLOR_YCBCR_FULL_RANGE };
struct drm_atomic_state { bool plane_color_pipeline; };
struct drm_plane_state {
	struct drm_atomic_state *state;
	enum drm_color_encoding color_encoding;
	enum drm_color_range color_range;
};

#include "color.inc"

static int dm_format(uint32_t fourcc, enum surface_pixel_format *out)
{
	struct { struct { uint32_t format; } *format; } fb_, *fb = &fb_;
	struct { uint32_t format; } info = { fourcc };
	struct { enum surface_pixel_format format; } plane_info_, *plane_info = &plane_info_;
	void *adev = NULL;

	(void)adev;
	fb->format = (void *)&info;
#include "dm_format.inc"
	*out = plane_info->format;
	return 0;
}

/* dpp401_dpp_setup's locals and format switch: the select and the default
 * color space. */
static void dpp_setup(enum surface_pixel_format format, enum dc_color_space input_color_space,
		      enum dc_color_space *out_color_space, enum dcn10_input_csc_select *out_select)
{
	uint32_t pixel_format = 0;
	uint32_t alpha_en = 1;
	enum dc_color_space color_space = COLOR_SPACE_SRGB;
	enum dcn10_input_csc_select select = INPUT_CSC_SELECT_BYPASS;
	uint32_t is_2bit = 0;
	uint32_t alpha_plane_enable = 0;

	(void)pixel_format;
	(void)alpha_en;
	(void)is_2bit;
	(void)alpha_plane_enable;
#include "dpp_setup.inc"
	*out_color_space = color_space;
	*out_select = select;
}

/* map_crtc_degamma_to_dc_plane's implicit degamma for the plane's format. */
static enum dc_transfer_func_predefined implicit_tf(enum surface_pixel_format format)
{
	struct { enum surface_pixel_format format; } plane_, *dc_plane_state = &plane_;
	enum dc_transfer_func_predefined tf = TRANSFER_FUNCTION_SRGB;

	dc_plane_state->format = format;
#include "degamma_tf.inc"
	return tf;
}

/* The register model the DPP functions write through. */
enum {
	REG_PRE_DEGAM,
	REG_CM_POST_CSC_CONTROL,
	REG_CM_POST_CSC_C11_C12,
	REG_CM_POST_CSC_C33_C34,
	REG_CM_POST_CSC_B_C11_C12,
	REG_CM_POST_CSC_B_C33_C34,
	REG_CUR0_MATRIX_MODE,
	REG_CUR0_MATRIX_C11_C12_A,
	REG_CUR0_MATRIX_C33_C34_A,
	REG_CUR0_MATRIX_C11_C12_B,
	REG_CUR0_MATRIX_C33_C34_B,
	REG_CURSOR0_CONTROL,
	REG_CURSOR0_COLOR0,
	REG_CURSOR0_COLOR1,
};
static uint32_t pre_degam_mode, pre_degam_select;
static uint32_t post_csc_mode, post_csc_current;
static int post_csc_set; /* -1 none, 0 A, 1 B */
static uint32_t cur_matrix_mode;
static uint32_t rec_rom_en, rec_cur_mode;

#define REG(r) REG_##r
#define REG_SET(reg, init, field, value) reg_set(REG_##reg, (value))
#define REG_SET_2(reg, init, f1, v1, f2, v2) (pre_degam_mode = (v1), pre_degam_select = (v2))
#define REG_GET(reg, field, out) (*(out) = reg_get(REG_##reg))
#define REG_UPDATE(reg, field, value) ((void)0)
#define REG_UPDATE_3(reg, f1, v1, f2, v2, f3, v3) (rec_cur_mode = (v1), rec_rom_en = (v3))

static void reg_set(int reg, uint32_t value)
{
	if (reg == REG_CM_POST_CSC_CONTROL)
		post_csc_mode = value;
	if (reg == REG_CUR0_MATRIX_MODE)
		cur_matrix_mode = value;
}
static uint32_t reg_get(int reg)
{
	if (reg == REG_CM_POST_CSC_CONTROL)
		return post_csc_current;
	return 0;
}

struct dc_context { int unused; };
struct color_matrices_reg {
	struct { uint32_t csc_c11, csc_c12; } shifts, masks;
	uint32_t csc_c11_c12, csc_c33_c34;
};
static void cm_helper_program_color_matrices(struct dc_context *ctx, const uint16_t *regval,
					     const struct color_matrices_reg *reg)
{
	(void)ctx;
	(void)regval;
	if (reg->csc_c11_c12 == REG_CM_POST_CSC_C11_C12)
		post_csc_set = 0;
	if (reg->csc_c11_c12 == REG_CM_POST_CSC_B_C11_C12)
		post_csc_set = 1;
}

struct out_csc_color_matrix { enum dc_color_space color_space; uint16_t regval[12]; };
struct tf_fields {
	uint32_t CM_POST_CSC_C11, CM_POST_CSC_C12;
	uint32_t CUR0_MATRIX_C11_A, CUR0_MATRIX_C12_A;
};
struct dc_cursor_attributes {
	enum dc_cursor_color_format color_format;
	union {
		struct { uint32_t ENABLE_CURSOR_DEGAMMA:1; } bits;
		uint32_t value;
	} attribute_flags;
};
struct dpp {
	struct dc_context *ctx;
	bool cursor_offload;
	struct { struct { struct { uint32_t expansion_mode, cur0_rom_en, mode; } bits; } cur0_ctl; } att;
};
struct dcn3_dpp {
	struct dpp base;
	const struct tf_fields *tf_shift, *tf_mask;
};
struct dcn401_dpp {
	struct dpp base;
	const struct tf_fields *tf_shift, *tf_mask;
};
#define TO_DCN30_DPP(d) ((struct dcn3_dpp *)(d))
#define TO_DCN401_DPP(d) ((struct dcn401_dpp *)(d))

#include "dpp_fns.inc"

int main(void)
{
	static const struct tf_fields fields;
	struct dcn401_dpp dpp = { .tf_shift = &fields, .tf_mask = &fields };
	struct dpp *dpp_base = &dpp.base;
	char fourcc[8];
	unsigned legacy, current, enc, range;

	while (scanf("%4s %u %u %u %u", fourcc, &legacy, &current, &enc, &range) == 5) {
		uint32_t f = DRM_FORMAT(fourcc[0], fourcc[1], fourcc[2], fourcc[3]);
		enum surface_pixel_format format;
		struct drm_plane_state state = { NULL, enc, range };
		enum dc_color_space cs, used;
		enum dcn10_input_csc_select select;
		struct dc_cursor_attributes cursor = {
			.color_format = CURSOR_MODE_COLOR_PRE_MULTIPLIED_ALPHA,
		};
		bool cm_is_degamma_srgb = legacy;
		bool gamma_corr = true;

		if (dm_format(f, &format) || fill_plane_color_attributes(&state, format, &cs)) {
			printf("-\n");
			continue;
		}
		/* amdgpu_dm_update_plane_color_mgmt: bypass, or under legacy gamma
		 * map_crtc_degamma_to_dc_plane's TF_TYPE_PREDEFINED input, which
		 * dcn32_set_input_transfer_func hands dpp3_set_pre_degam. */
		dpp3_set_pre_degam(dpp_base, legacy ? implicit_tf(format) : TRANSFER_FUNCTION_LINEAR);
		/* dpp401_dpp_setup's post CSC from a pipe whose
		 * CM_POST_CSC_MODE_CURRENT reads `current`. */
		dpp_setup(format, cs, &used, &select);
		post_csc_current = current;
		post_csc_set = -1;
		dpp3_program_post_csc(dpp_base, used, select, NULL);
		/* hwseq step 8, then the cursor's attributes. */
		cur_matrix_mode = 0xff;
		dpp401_set_cursor_matrix(dpp_base, used, (struct dc_csc_transform){ 0 });
#include "cursor_degamma.inc"
		dpp401_set_cursor_attributes(dpp_base, &cursor);
		printf("%u %u %u %s %u %u\n", pre_degam_mode, pre_degam_select, post_csc_mode,
		       post_csc_set < 0 ? "-" : post_csc_set ? "B" : "A", cur_matrix_mode, rec_rom_en);
	}
	return 0;
}
