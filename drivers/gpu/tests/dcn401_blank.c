/* Native fetch-stop witnesses and fresh frame counter used by blank startup.
 * cc -Wall -Wextra -Werror -I/usr/src/linux/drivers/gpu/drm/amd/include \
 *    drivers/gpu/tests/dcn401_blank.c -o /tmp/narf-dcn401-blank
 */
#include "asic_reg/dcn/dcn_4_1_0_offset.h"
#include "asic_reg/dcn/dcn_4_1_0_sh_mask.h"
#define EQ(a,b) _Static_assert((unsigned)(a) == (unsigned)(b), #a)
#define REG(a,b) EQ(reg##a,b); EQ(reg##a##_BASE_IDX,2)
#define PIPE(i) \
 REG(HUBP##i##_DCHUBP_CNTL,0x5f4+0xdc*(i)); \
 REG(HUBP##i##_HUBP_CLK_CNTL,0x5f5+0xdc*(i)); \
 REG(CURSOR0_##i##_CURSOR_CONTROL,0x679+0xdc*(i)); \
 REG(CURSOR0_##i##_DMDATA_CNTL,0x685+0xdc*(i)); \
 REG(OTG##i##_OTG_STATUS_FRAME_COUNT,0x1b4d+0x80*(i)); \
 EQ(HUBP##i##_DCHUBP_CNTL__HUBP_BLANK_EN_MASK,1); \
 EQ(HUBP##i##_DCHUBP_CNTL__HUBP_NO_OUTSTANDING_REQ_MASK,2); \
 EQ(HUBP##i##_DCHUBP_CNTL__HUBP_SOFT_RESET_MASK,4); \
 EQ(HUBP##i##_DCHUBP_CNTL__HUBP_TTU_DISABLE_MASK,0x1000); \
 EQ(HUBP##i##_HUBP_CLK_CNTL__HUBP_CLOCK_ENABLE_MASK,1); \
 EQ(CURSOR0_##i##_CURSOR_CONTROL__CURSOR_ENABLE_MASK,1); \
 EQ(CURSOR0_##i##_DMDATA_CNTL__DMDATA_UPDATED_MASK,1); \
 EQ(CURSOR0_##i##_DMDATA_CNTL__DMDATA_REPEAT_MASK,2); \
 EQ(CURSOR0_##i##_DMDATA_CNTL__DMDATA_MODE_MASK,4); \
 EQ(CURSOR0_##i##_DMDATA_CNTL__DMDATA_SIZE_MASK,0xfff0000); \
 EQ(OTG##i##_OTG_STATUS_FRAME_COUNT__OTG_FRAME_COUNT_MASK,0xffffff)
PIPE(0); PIPE(1); PIPE(2); PIPE(3);
int main(void) { return 0; }
