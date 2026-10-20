/* Host stand-in for DC's dc.h: the color types color_gamma.c and
 * dcn30_cm_common.c use, copied from Linux's dc.h (the real header pulls in
 * the whole DC core). */
#ifndef NARF_COLOR_DC_H
#define NARF_COLOR_DC_H
#include "os_types.h"
#include "include/fixed31_32.h"
#include "hw_shared.h"
struct rom_curve_caps {
	uint16_t srgb : 1;
	uint16_t bt2020 : 1;
	uint16_t gamma2_2 : 1;
	uint16_t pq : 1;
	uint16_t hlg : 1;
};
struct dpp_color_caps {
	uint16_t dcn_arch : 1;
	uint16_t input_lut_shared : 1;
	uint16_t icsc : 1;
	uint16_t dgam_ram : 1;
	uint16_t post_csc : 1;
	uint16_t gamma_corr : 1;
	uint16_t hw_3d_lut : 1;
	uint16_t ogam_ram : 1;
	uint16_t ocsc : 1;
	uint16_t dgam_rom_for_yuv : 1;
	uint16_t upsp_pre_scaler : 1;
	struct rom_curve_caps dgam_rom_caps;
	struct rom_curve_caps ogam_rom_caps;
};
struct dc_color_caps {
	struct dpp_color_caps dpp;
};
enum {
	TRANSFER_FUNC_POINTS = 1025
};
enum dc_transfer_func_type {
	TF_TYPE_PREDEFINED,
	TF_TYPE_DISTRIBUTED_POINTS,
	TF_TYPE_BYPASS,
	TF_TYPE_HWPWL
};
struct dc_transfer_func_distributed_points {
	struct fixed31_32 red[TRANSFER_FUNC_POINTS];
	struct fixed31_32 green[TRANSFER_FUNC_POINTS];
	struct fixed31_32 blue[TRANSFER_FUNC_POINTS];
	uint16_t end_exponent;
	uint16_t x_point_at_y1_red;
	uint16_t x_point_at_y1_green;
	uint16_t x_point_at_y1_blue;
};
enum dc_transfer_func_predefined {
	TRANSFER_FUNCTION_SRGB,
	TRANSFER_FUNCTION_BT709,
	TRANSFER_FUNCTION_PQ,
	TRANSFER_FUNCTION_LINEAR,
	TRANSFER_FUNCTION_UNITY,
	TRANSFER_FUNCTION_HLG,
	TRANSFER_FUNCTION_HLG12,
	TRANSFER_FUNCTION_GAMMA22,
	TRANSFER_FUNCTION_GAMMA24,
	TRANSFER_FUNCTION_GAMMA26
};
struct dc_transfer_func {
	struct kref refcount;
	enum dc_transfer_func_type type;
	enum dc_transfer_func_predefined tf;
	uint32_t sdr_ref_white_level;
	struct fixed31_32 hdr_multiplier;
	union {
		struct pwl_params pwl;
		struct dc_transfer_func_distributed_points tf_pts;
	};
};
#endif
