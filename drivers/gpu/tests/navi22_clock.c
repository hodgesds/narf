/* Navi22 clock request wire contract, checked against primary Linux headers.
 * cc -std=c11 -Wall -Wextra -Werror -D'__counted_by(x)=' \
 *    -I<linux>/drivers/gpu/drm/amd/include \
 *    -I<linux>/drivers/gpu/drm/amd/display/dc/clk_mgr/dcn30 \
 *    -I<linux>/drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if \
 *    drivers/gpu/tests/navi22_clock.c -o /tmp/narf-navi22-clock
 * Run the resulting binary. DAL and PPSMC have different message spaces.
 */
#include <stddef.h>
#include <stdint.h>
#include "dalsmc.h"
#include "dcn30_smu11_driver_if.h"
#include "smu_v11_0_7_ppsmc.h"
#include "atomfirmware.h"
#include "asic_reg/mp/mp_11_0_offset.h"
#include "asic_reg/dcn/dcn_3_0_0_offset.h"
#include "asic_reg/dcn/dcn_3_0_0_sh_mask.h"

#define EQ(a, b) _Static_assert((unsigned long)(a) == (unsigned long)(b), #a)

EQ(DALSMC_VERSION, 1);
EQ(DALSMC_Result_OK, 1);
EQ(DALSMC_Result_Failed, 0xff);
EQ(DALSMC_Result_UnknownCmd, 0xfe);
EQ(DALSMC_Result_CmdRejectedPrereq, 0xfd);
EQ(DALSMC_Result_CmdRejectedBusy, 0xfc);
EQ(DALSMC_MSG_GetSmuVersion, 2);
EQ(DALSMC_MSG_GetDriverIfVersion, 3);
EQ(DALSMC_MSG_GetMsgHeaderVersion, 4);
EQ(DALSMC_MSG_SetDalDramAddrHigh, 5);
EQ(DALSMC_MSG_SetDalDramAddrLow, 6);
EQ(DALSMC_MSG_TransferTableDram2Smu, 8);
EQ(DALSMC_MSG_SetHardMinByFreq, 9);
EQ(DALSMC_MSG_GetDpmFreqByIndex, 0xb);
EQ(DALSMC_MSG_SetMinDeepSleepDcefclk, 0xd);
EQ(DALSMC_MSG_NumOfDisplays, 0xe);
EQ(DALSMC_MSG_BacoAudioD3PME, 0x11);
EQ(PPCLK_GFXCLK, 0);
EQ(PPCLK_SOCCLK, 1);
EQ(PPCLK_UCLK, 2);
EQ(PPCLK_FCLK, 3);
EQ(PPCLK_DCEFCLK, 8);
EQ(PPCLK_DISPCLK, 9);
EQ(PPCLK_PIXCLK, 10);
EQ(PPCLK_PHYCLK, 11);
EQ(PPSMC_MSG_GetSmuVersion, 2);
EQ(PPSMC_MSG_GetDriverIfVersion, 3);
EQ(PPSMC_MSG_SetAllowedFeaturesMaskLow, 4);
EQ(PPSMC_MSG_SetAllowedFeaturesMaskHigh, 5);
EQ(PPSMC_MSG_EnableAllSmuFeatures, 6);
EQ(PPSMC_MSG_EnableSmuFeaturesLow, 8);
EQ(PPSMC_MSG_EnableSmuFeaturesHigh, 9);
EQ(PPSMC_MSG_DisableSmuFeaturesLow, 0xa);
EQ(PPSMC_MSG_DisableSmuFeaturesHigh, 0xb);
EQ(PPSMC_MSG_GetRunningSmuFeaturesLow, 0xc);
EQ(PPSMC_MSG_GetRunningSmuFeaturesHigh, 0xd);
EQ(PPSMC_MSG_SetSoftMinByFreq, 0x19);
EQ(PPSMC_MSG_SetSoftMaxByFreq, 0x1a);
EQ(PPSMC_MSG_GetMinDpmFreq, 0x1d);
EQ(PPSMC_MSG_GetMaxDpmFreq, 0x1e);
EQ(PPSMC_MSG_AllowGfxOff, 0x28);
EQ(PPSMC_MSG_DisallowGfxOff, 0x29);
EQ(mmMP1_SMN_C2PMSG_74, 0x28a);
EQ(mmMP1_SMN_C2PMSG_51, 0x273);
EQ(mmMP1_SMN_C2PMSG_52, 0x274);
EQ(mmMP1_SMN_C2PMSG_66, 0x282);
EQ(mmMP1_SMN_C2PMSG_82, 0x292);
EQ(mmMP1_SMN_C2PMSG_90, 0x29a);
EQ(mmDENTIST_DISPCLK_CNTL, 0x64);
EQ(mmDENTIST_DISPCLK_CNTL_BASE_IDX, 1);
EQ(DENTIST_DISPCLK_CNTL__DENTIST_DISPCLK_WDIVIDER_MASK, 0x7f);
EQ(DENTIST_DISPCLK_CNTL__DENTIST_DISPCLK_RDIVIDER_MASK, 0x7f00);
EQ(DENTIST_DISPCLK_CNTL__DENTIST_DISPCLK_CHG_DONE_MASK, 1 << 19);
EQ(DENTIST_DISPCLK_CNTL__DENTIST_DPPCLK_CHG_DONE_MASK, 1 << 20);
EQ(DENTIST_DISPCLK_CNTL__DENTIST_DPPCLK_WDIVIDER_MASK, 0x7f000000);
EQ(mmDPPCLK0_DTO_PARAM, 0x99);
EQ(mmDPPCLK5_DTO_PARAM, 0x9e);
EQ(mmDPPCLK_DTO_CTRL, 0xb6);
EQ(DPPCLK0_DTO_PARAM__DPPCLK0_DTO_PHASE_MASK, 0xff);
EQ(DPPCLK0_DTO_PARAM__DPPCLK0_DTO_MODULO_MASK, 0xff0000);
EQ(sizeof(struct set_pixel_clock_parameter_v1_7), 16);
EQ(offsetof(struct set_pixel_clock_parameter_v1_7, pixclk_100hz), 0);
EQ(offsetof(struct set_pixel_clock_parameter_v1_7, miscinfo), 7);
EQ(offsetof(struct set_pixel_clock_parameter_v1_7, crtc_id), 8);
EQ(offsetof(struct set_pixel_clock_parameter_v1_7, deep_color_ratio), 9);
EQ(ATOM_COMBOPHY_PLL0, 20);
EQ(ATOM_CRTC1, 0);
EQ(PIXEL_CLOCK_V7_MISC_REF_DIV_SRC_XTALIN, 0);
EQ(PIXEL_CLOCK_V7_DEEPCOLOR_RATIO_DIS, 0);

int main(void) { return 0; }
