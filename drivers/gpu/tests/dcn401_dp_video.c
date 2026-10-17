/* Native DP video ratio/control layout; independent of the Rust model.
 * cc -Wall -Wextra -Werror -I/usr/src/linux/drivers/gpu/drm/amd/include \
 *    drivers/gpu/tests/dcn401_dp_video.c -o /tmp/narf-dcn401-dp-video
 */
#include "asic_reg/dcn/dcn_4_1_0_offset.h"
#include "asic_reg/dcn/dcn_4_1_0_sh_mask.h"
#define EQ(a,b) _Static_assert((unsigned)(a) == (unsigned)(b), #a)
#define REG(a,b) EQ(reg##a,b); EQ(reg##a##_BASE_IDX,2)
#define VIDEO(i) \
 REG(DP##i##_DP_VID_TIMING,0x2126+0x124*(i)); \
 REG(DP##i##_DP_VID_N,0x2127+0x124*(i)); \
 REG(DP##i##_DP_VID_M,0x2128+0x124*(i)); \
 EQ(DP##i##_DP_VID_TIMING__DP_VID_M_N_DOUBLE_BUFFER_MODE_MASK,0x10); \
 EQ(DP##i##_DP_VID_TIMING__DP_VID_M_N_GEN_EN_MASK,0x100); \
 EQ(DP##i##_DP_VID_TIMING__DP_VID_M_DIV_MASK,0x3000); \
 EQ(DP##i##_DP_VID_TIMING__DP_VID_N_INTERVAL_MASK,0xc000); \
 EQ(DP##i##_DP_VID_TIMING__DP_VID_N_INTERVAL__SHIFT,14); \
 EQ(DP##i##_DP_VID_TIMING__DP_VID_N_DIV_MASK,0xff000000); \
 EQ(DP##i##_DP_VID_N__DP_VID_N_MASK,0xffffff); \
 EQ(DP##i##_DP_VID_M__DP_VID_M_MASK,0xffffff); \
 EQ(DP##i##_DP_VID_STREAM_CNTL__DP_VID_STREAM_ENABLE_MASK,1); \
 EQ(DP##i##_DP_VID_STREAM_CNTL__DP_VID_STREAM_DIS_DEFER_MASK,0x300); \
 EQ(DP##i##_DP_VID_STREAM_CNTL__DP_VID_STREAM_STATUS_MASK,0x10000); \
 EQ(DP##i##_DP_STEER_FIFO__DP_STEER_FIFO_ENABLE_MASK,1); \
 EQ(DP##i##_DP_STEER_FIFO__DP_STEER_FIFO_RESET_MASK,2); \
 EQ(DP##i##_DP_STEER_FIFO__DP_STEER_FIFO_RESET_DONE_MASK,4)
VIDEO(0); VIDEO(1); VIDEO(2); VIDEO(3);
int main(void) { return 0; }
