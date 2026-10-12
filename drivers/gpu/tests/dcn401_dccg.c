/* Native DCN401 divider layout, checked against Linux's DCN 4.1.0 headers.
 * cc -Wall -Wextra -Werror -I/usr/src/linux/drivers/gpu/drm/amd/include \
 *    drivers/gpu/tests/dcn401_dccg.c -o /tmp/narf-dcn401-dccg
 */
#include "asic_reg/dcn/dcn_4_1_0_offset.h"
#include "asic_reg/dcn/dcn_4_1_0_sh_mask.h"
#define EQ(a,b) _Static_assert((unsigned)(a) == (unsigned)(b), #a)
#define REG(a,b) EQ(reg##a,b); EQ(reg##a##_BASE_IDX,1)
EQ(regDCCG_GATE_DISABLE_CNTL3,0x5a);
EQ(regDCCG_GATE_DISABLE_CNTL3_BASE_IDX,2);
REG(DENTIST_DISPCLK_CNTL,0x64);
REG(DTBCLK_P_CNTL,0x68);
REG(DCCG_GATE_DISABLE_CNTL5,0x69);
REG(OTG_PIXEL_RATE_DIV,0x6f);
REG(DPPCLK_CTRL,0xa8);
EQ(DENTIST_DISPCLK_CNTL__DENTIST_DISPCLK_CHG_DONE_MASK,1<<19);
#define PIPE(i) \
 REG(DPPCLK##i##_DTO_PARAM,0x99+(i)); \
 EQ(DPPCLK##i##_DTO_PARAM__DPPCLK##i##_DTO_PHASE_MASK,0xff); \
 EQ(DPPCLK##i##_DTO_PARAM__DPPCLK##i##_DTO_MODULO_MASK,0xff0000); \
 EQ(DPPCLK_CTRL__DPPCLK##i##_EN_MASK,1<<(3*(i))); \
 REG(OTG##i##_PIXEL_RATE_CNTL,0x80+4*(i)); \
 REG(DP_DTO##i##_PHASE,0x81+4*(i)); \
 REG(DP_DTO##i##_MODULO,0x82+4*(i)); \
 EQ(OTG##i##_PIXEL_RATE_CNTL__DP_DTO##i##_ENABLE_MASK,0x10); \
 EQ(OTG##i##_PIXEL_RATE_CNTL__PIPE##i##_DTO_SRC_SEL_MASK,0x1000); \
 EQ(OTG_PIXEL_RATE_DIV__OTG##i##_TMDS_PIXEL_RATE_DIV_MASK,1<<(5*(i))); \
 EQ(OTG_PIXEL_RATE_DIV__DPDTO##i##_INT_MASK,15<<(5*(i)+1)); \
 EQ(DTBCLK_P_CNTL__DTBCLK_P##i##_SRC_SEL_MASK,3<<(3*(i))); \
 EQ(DTBCLK_P_CNTL__DTBCLK_P##i##_EN_MASK,4<<(3*(i))); \
 EQ(DCCG_GATE_DISABLE_CNTL5__DTBCLK_P##i##_GATE_DISABLE_MASK,1<<(i)); \
 EQ(DCCG_GATE_DISABLE_CNTL3__SYMCLK32_ROOT_SE##i##_GATE_DISABLE_MASK | \
    DCCG_GATE_DISABLE_CNTL3__SYMCLK32_SE##i##_GATE_DISABLE_MASK,3<<(8+2*(i))); \
 EQ(DCCG_GATE_DISABLE_CNTL3__SYMCLK32_ROOT_LE##i##_GATE_DISABLE_MASK | \
    DCCG_GATE_DISABLE_CNTL3__SYMCLK32_LE##i##_GATE_DISABLE_MASK,3<<(20+2*(i)))
PIPE(0); PIPE(1); PIPE(2); PIPE(3);
int main(void) { return 0; }
