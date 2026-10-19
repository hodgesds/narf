/* Independent Linux SMU14.0.2 metrics, board-limit and runtime DPM checks.
 * cc -Wall -Wextra -Werror '-D__counted_by(x)=' \
 * -I/usr/src/linux/drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if \
 * -I/usr/src/linux/drivers/gpu/drm/amd/pm/swsmu/inc \
 * -I/usr/src/linux/drivers/gpu/drm/amd/include \
 * drivers/gpu/tests/smu14_metrics.c -o /tmp/narf-smu14-metrics
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "atomfirmware.h"
#include "smu14_driver_if_v14_0.h"
#include "smu_v14_0_2_ppsmc.h"
#include "smu_v14_0_2_pptable.h"
#define EQ(a,b) _Static_assert((unsigned)(a) == (unsigned)(b), #a)
#define M(f) offsetof(SmuMetrics_t, f)
#define C(f) (offsetof(struct smu_14_0_2_powerplay_table, smc_pptable) + \
              offsetof(PPTable_t, CustomSkuTable) + offsetof(CustomSkuTable_t, f))
EQ(TABLE_SMU_METRICS, 5);
EQ(sizeof(SmuMetricsExternal_t), 412);
EQ(M(CurrClock), 0); EQ(PPCLK_SOCCLK, 1); EQ(PPCLK_UCLK, 2); EQ(PPCLK_FCLK, 3);
EQ(PPCLK_DCFCLK, 9); EQ(PPCLK_GFXCLK, 0);
EQ(M(AverageGfxclkFrequencyPreDs), 46); EQ(M(AverageGfxclkFrequencyPostDs), 48);
EQ(M(AverageFclkFrequencyPreDs), 50); EQ(M(AverageFclkFrequencyPostDs), 52);
EQ(M(AverageMemclkFrequencyPreDs), 54); EQ(M(AverageMemclkFrequencyPostDs), 56);
EQ(M(MetricsCounter), 104); EQ(M(AvgVoltage), 108); EQ(SVI_PLANE_VDD_GFX, 0);
EQ(M(AverageGfxActivity), 124); EQ(M(AverageUclkActivity), 126);
EQ(M(AverageSocketPower), 136); EQ(M(AverageTotalBoardPower), 138);
EQ(M(AvgTemperature), 140); EQ(TEMP_EDGE, 0); EQ(TEMP_HOTSPOT, 1); EQ(TEMP_MEM, 4);
EQ(TEMP_VR_GFX, 5); EQ(TEMP_VR_SOC, 6);
EQ(M(PcieRate), 166); EQ(M(PcieWidth), 167); EQ(M(AvgFanPwm), 168);
EQ(M(AvgFanRpm), 170); EQ(M(ThrottlingPercentage), 172); EQ(THROTTLER_COUNT, 21);
EQ(THROTTLER_TEMP_HOTSPOT_BIT, 1); EQ(THROTTLER_PPT0_BIT, 14);
EQ(THROTTLER_GFX_DVO_BIT, 20);
EQ(sizeof(struct smu_14_0_2_powerplay_table), 5812);
EQ(offsetof(struct smu_14_0_2_powerplay_table, software_shutdown_temp), 43);
EQ(C(SocketPowerLimitAc), 4924); EQ(PPT_THROTTLER_PPT0, 0);
EQ(C(TemperatureLimit), 4944); EQ(C(FanMaximumRpm), 5046);
EQ(C(FanAbnormalTempLimitOffset), 5126); EQ(sizeof(CustomSkuTable_t), 360);
EQ((1u << FEATURE_THROTTLERS_BIT) | (1u << FEATURE_GTHR_BIT) |
   (1u << FEATURE_ACDC_BIT) | (1u << FEATURE_VR0HOT_BIT) |
   (1u << FEATURE_FW_CTF_BIT) | (1u << FEATURE_FAN_CONTROL_BIT), 0x3e800000);
EQ(FEATURE_FAN_ABNORMAL_BIT, 57);
EQ((1u << FEATURE_DS_GFXCLK_BIT) | (1u << FEATURE_GFX_ULV_BIT), 0x10400);
EQ((1u << FEATURE_DS_SOCCLK_BIT) | (1u << FEATURE_DS_FCLK_BIT) |
   (1u << FEATURE_DS_LCLK_BIT) | (1u << FEATURE_DS_DCFCLK_BIT) |
   (1u << FEATURE_DS_UCLK_BIT), 0xf800);
EQ(PPSMC_MSG_EnableSmuFeaturesLow, 8); EQ(PPSMC_MSG_EnableSmuFeaturesHigh, 9);
EQ(PPSMC_MSG_TransferTableSmu2Dram, 0x12);
EQ(PPSMC_MSG_SetSoftMinByFreq, 0x19); EQ(PPSMC_MSG_SetSoftMaxByFreq, 0x1a);
EQ(PPSMC_MSG_GetPptLimit, 0x33);
EQ(PPSMC_MSG_PowerUpVcn, 0x2a); EQ(PPSMC_MSG_PowerDownVcn, 0x2b);
EQ(FEATURE_MM_DPM_BIT, 20); EQ(FEATURE_DS_VCN_BIT, 44);
int main(void) { return 0; }
