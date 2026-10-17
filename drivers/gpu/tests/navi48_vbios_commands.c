/* DMUB VBIOS payload contract for the native TMDS bring-up commands.
 * cc -Wall -Wextra -Werror -D'__counted_by(x)=' \
 *    -I/usr/src/linux/drivers/gpu/drm/amd/include \
 *    drivers/gpu/tests/navi48_vbios_commands.c -o /tmp/narf-navi48-vbios
 * payload_bytes is sizeof(cmd) - sizeof(header), so these sizes are the
 * header's fourth byte; field offsets are relative to the 4-byte header.
 */
#include <stddef.h>
#include <stdint.h>
#include "atomfirmware.h"
#define EQ(a,b) _Static_assert((unsigned long)(a) == (unsigned long)(b), #a)
#define AT(s,f,o) EQ(offsetof(struct s, f), o)
/* DIGX_ENCODER_CONTROL (sub_type 0): union dig_encoder_control_parameters_v1_5. */
EQ(sizeof(union dig_encoder_control_parameters_v1_5), 12);
AT(dig_encoder_stream_setup_parameters_v1_5, digid, 0);
AT(dig_encoder_stream_setup_parameters_v1_5, action, 1);
AT(dig_encoder_stream_setup_parameters_v1_5, digmode, 2);
AT(dig_encoder_stream_setup_parameters_v1_5, lanenum, 3);
AT(dig_encoder_stream_setup_parameters_v1_5, pclk_10khz, 4);
AT(dig_encoder_stream_setup_parameters_v1_5, bitpercolor, 8);
EQ(ATOM_ENCODER_CMD_STREAM_SETUP, 0x0f);
EQ(ATOM_ENCODER_MODE_HDMI, 3);
/* DIG1_TRANSMITTER_CONTROL (sub_type 1): the v1.6/v1.7 union is 16 bytes. */
EQ(sizeof(struct dig_transmitter_control_parameters_v1_6), 16);
/* SET_PIXEL_CLOCK (sub_type 2). */
EQ(sizeof(struct set_pixel_clock_parameter_v1_7), 16);
AT(set_pixel_clock_parameter_v1_7, pixclk_100hz, 0);
AT(set_pixel_clock_parameter_v1_7, pll_id, 4);
AT(set_pixel_clock_parameter_v1_7, encoderobjid, 5);
AT(set_pixel_clock_parameter_v1_7, encoder_mode, 6);
AT(set_pixel_clock_parameter_v1_7, miscinfo, 7);
AT(set_pixel_clock_parameter_v1_7, crtc_id, 8);
AT(set_pixel_clock_parameter_v1_7, deep_color_ratio, 9);
EQ(ATOM_COMBOPHY_PLL0, 20);
EQ(ATOM_COMBOPHY_PLL3, 23);
EQ(ATOM_CRTC1, 0);
EQ(PIXEL_CLOCK_V7_MISC_REF_DIV_SRC_XTALIN, 0);
EQ(PIXEL_CLOCK_V7_DEEPCOLOR_RATIO_DIS, 0);
int main(void) { return 0; }
