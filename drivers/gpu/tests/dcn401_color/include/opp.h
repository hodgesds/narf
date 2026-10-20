/* Host stand-in for DC's inc/hw/opp.h: the color module's structs, copied
 * from Linux's opp.h (the real header pulls in the scaler library). */
#ifndef NARF_COLOR_OPP_H
#define NARF_COLOR_OPP_H
#include "dc.h"
struct gamma_pixel {
	struct fixed31_32 r;
	struct fixed31_32 g;
	struct fixed31_32 b;
};
enum channel_name {
	CHANNEL_NAME_RED,
	CHANNEL_NAME_GREEN,
	CHANNEL_NAME_BLUE
};
struct custom_float_format {
	uint32_t mantissa_bits;
	uint32_t exponenta_bits;
	bool sign;
};
struct hw_x_point {
	uint32_t custom_float_x;
	struct fixed31_32 x;
	struct fixed31_32 regamma_y_red;
	struct fixed31_32 regamma_y_green;
	struct fixed31_32 regamma_y_blue;
};
struct pwl_float_data_ex {
	struct fixed31_32 r;
	struct fixed31_32 g;
	struct fixed31_32 b;
	struct fixed31_32 delta_r;
	struct fixed31_32 delta_g;
	struct fixed31_32 delta_b;
};
enum hw_point_position {
	HW_POINT_POSITION_MIDDLE,
	HW_POINT_POSITION_LEFT,
	HW_POINT_POSITION_RIGHT
};
struct gamma_point {
	int32_t left_index;
	int32_t right_index;
	enum hw_point_position pos;
	struct fixed31_32 coeff;
};
struct pixel_gamma_point {
	struct gamma_point r;
	struct gamma_point g;
	struct gamma_point b;
};
struct gamma_coefficients {
	struct fixed31_32 a0[3];
	struct fixed31_32 a1[3];
	struct fixed31_32 a2[3];
	struct fixed31_32 a3[3];
	struct fixed31_32 user_gamma[3];
	struct fixed31_32 user_contrast;
	struct fixed31_32 user_brightness;
};
struct pwl_float_data {
	struct fixed31_32 r;
	struct fixed31_32 g;
	struct fixed31_32 b;
};
#endif
