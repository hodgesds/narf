/* Linux reference for the DCN4 plane input conversion; see check.sh.
 *
 * check.sh extracts, verbatim: enum surface_pixel_format and enum
 * dc_color_space (dc_hw_types.h), dpp_input_csc_matrix (dc/inc/hw/dpp.h),
 * amdgpu_dm's fill_plane_color_attributes and fill_dc_plane_info_and_addr's
 * DRM-to-DC format switch, dpp401_dpp_setup's format switch with its
 * default color space, and hubp2_program_pixel_format.
 * dpp3_program_post_csc's matrix lookup and cm_helper_program_color_matrices'
 * packing are a few lines each and need the whole DPP; they are restated
 * below (the select is INPUT_CSC_SELECT_ICSC on a pipe whose
 * CM_POST_CSC_MODE_CURRENT reads bypass, as a newly staged pipe's does).
 *
 * Input lines: <fourcc> <COLOR_ENCODING> <COLOR_RANGE>
 * Output: "-" when amdgpu_dm refuses the plane (fill_plane_color_attributes
 *   -EINVAL), else HUBP pixel format and crossbar (CB_B, CR_R), CNVC pixel
 *   format, ALPHA_EN, CM_POST_CSC_MODE, then for a non-bypass select the six
 *   CM_POST_CSC_C11_C12..C33_C34 words (hex).
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

#include "linux.inc"

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

/* dpp401_dpp_setup's locals and switch. */
static void dpp_setup(enum surface_pixel_format format, enum dc_color_space input_color_space,
		      uint32_t *out_pixel_format, uint32_t *out_alpha_en,
		      enum dc_color_space *out_color_space, enum dcn10_input_csc_select *out_select)
{
	uint32_t pixel_format = 0;
	uint32_t alpha_en = 1;
	enum dc_color_space color_space = COLOR_SPACE_SRGB;
	enum dcn10_input_csc_select select = INPUT_CSC_SELECT_BYPASS;
	uint32_t is_2bit = 0;
	uint32_t alpha_plane_enable = 0;

	(void)is_2bit;
	(void)alpha_plane_enable;
#include "dpp_setup.inc"
	*out_pixel_format = pixel_format;
	*out_alpha_en = alpha_en;
	*out_color_space = color_space;
	*out_select = select;
}

/* hubp2_program_pixel_format, recording its two register updates. */
struct hubp { int unused; };
static uint32_t hubp_format, cb_b, cr_r;
struct dcn20_hubp;
#define TO_DCN20_HUBP(h) ((struct dcn20_hubp *)(h))
#define BREAK_TO_DEBUGGER() ((void)0)
#define REG_UPDATE_2(reg, f1, v1, f2, v2) (cb_b = (v1), cr_r = (v2))
#define REG_UPDATE(reg, f, v) (hubp_format = (v))
#include "hubp_fn.inc"

int main(void)
{
	char fourcc[8];
	unsigned enc, range;

	while (scanf("%4s %u %u", fourcc, &enc, &range) == 3) {
		uint32_t f = DRM_FORMAT(fourcc[0], fourcc[1], fourcc[2], fourcc[3]);
		enum surface_pixel_format format;
		struct drm_plane_state state = { NULL, enc, range };
		enum dc_color_space cs, used;
		enum dcn10_input_csc_select select;
		uint32_t pixel_format, alpha_en;
		struct hubp h;

		if (dm_format(f, &format) || fill_plane_color_attributes(&state, format, &cs)) {
			printf("-\n");
			continue;
		}
		hubp2_program_pixel_format(&h, format);
		dpp_setup(format, cs, &pixel_format, &alpha_en, &used, &select);
		printf("%u %u %u %u %u %u", hubp_format, cb_b, cr_r, pixel_format, alpha_en, select);
		if (select != INPUT_CSC_SELECT_BYPASS) {
			/* dpp3_program_post_csc: the table entry of the color space. */
			const uint16_t *regval = NULL;
			for (unsigned i = 0; i < sizeof(dpp_input_csc_matrix) / sizeof(dpp_input_csc_matrix[0]); i++)
				if (dpp_input_csc_matrix[i].color_space == used) {
					regval = dpp_input_csc_matrix[i].regval;
					break;
				}
			if (!regval) {
				printf(" none\n");
				continue;
			}
			/* cm_helper_program_color_matrices: C11 | C12 << 16, ... */
			for (int i = 0; i < 6; i++)
				printf(" %x", (unsigned)regval[2 * i] | (unsigned)regval[2 * i + 1] << 16);
		}
		printf("\n");
	}
	return 0;
}
