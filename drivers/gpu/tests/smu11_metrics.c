/* Independent Linux SMU11 (sienna_cichlid / navy_flounder) metrics, board
 * limit and PPSMC checks for amdgpu_smu_navi22_telemetry.rs.
 * cc -Wall -Wextra -Werror '-D__counted_by(x)=' \
 * -I/usr/src/linux/drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if \
 * -I/usr/src/linux/drivers/gpu/drm/amd/pm/swsmu/inc \
 * -I/usr/src/linux/drivers/gpu/drm/amd/include \
 * drivers/gpu/tests/smu11_metrics.c -o /tmp/narf-smu11-metrics
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "atomfirmware.h"
#include "smu11_driver_if_sienna_cichlid.h"
#include "smu_v11_0_7_ppsmc.h"
#include "smu_v11_0_7_pptable.h"
#define EQ(a,b) _Static_assert((unsigned)(a) == (unsigned)(b), #a)
#define M1(f) offsetof(SmuMetrics_t, f)
#define M2(f) offsetof(SmuMetrics_V2_t, f)
#define M3(f) offsetof(SmuMetrics_V3_t, f)
#define PB(f) offsetof(PPTable_beige_goby_t, f)
#define P(f) offsetof(PPTable_t, f)
EQ(TABLE_SMU_METRICS, 5); EQ(TABLE_PPTABLE, 0);
EQ(sizeof(SmuMetricsExternal_t), 200); EQ(sizeof(PPTable_t), 1668);
EQ(PPCLK_GFXCLK, 0); EQ(PPCLK_SOCCLK, 1); EQ(PPCLK_UCLK, 2); EQ(PPCLK_FCLK, 3);
EQ(PPCLK_DCEFCLK, 8);
/* Shared prefix of both union members used for NARF decoding. */
EQ(M1(CurrClock), 0); EQ(M2(CurrClock), 0);
EQ(M1(AverageGfxclkFrequencyPreDs), 52); EQ(M2(AverageGfxclkFrequencyPreDs), 52);
EQ(M1(AverageGfxclkFrequencyPostDs), 54); EQ(M2(AverageGfxclkFrequencyPostDs), 54);
EQ(M1(AverageFclkFrequencyPostDs), 58); EQ(M2(AverageFclkFrequencyPostDs), 58);
EQ(M1(AverageUclkFrequencyPostDs), 62); EQ(M2(AverageUclkFrequencyPostDs), 62);
EQ(M1(AverageGfxActivity), 64); EQ(M2(AverageGfxActivity), 64);
EQ(M1(AverageUclkActivity), 66); EQ(M2(AverageUclkActivity), 66);
EQ(M1(AverageSocketPower), 72); EQ(M2(AverageSocketPower), 72);
EQ(M1(TemperatureEdge), 74); EQ(M2(TemperatureEdge), 74);
EQ(M1(TemperatureHotspot), 76); EQ(M2(TemperatureHotspot), 76);
EQ(M1(TemperatureMem), 78); EQ(M2(TemperatureMem), 78);
EQ(M1(TemperatureVrGfx), 80); EQ(M2(TemperatureVrGfx), 80);
EQ(M1(TemperatureVrSoc), 86); EQ(M2(TemperatureVrSoc), 86);
/* Where the layouts diverge. */
EQ(M1(ThrottlerStatus), 96); EQ(M1(CurrFanSpeed), 102); EQ(M1(PcieRate), 130);
EQ(M1(PcieWidth), 131);
EQ(M2(ThrottlingPercentage), 100); EQ(THROTTLER_COUNT, 20);
EQ(M3(CurrClock), 0); EQ(M3(AverageGfxclkFrequencyPreDs), 52);
EQ(M3(AverageGfxclkFrequencyPostDs), 54); EQ(M3(AverageFclkFrequencyPostDs), 58);
EQ(M3(AverageUclkFrequencyPostDs), 62); EQ(M3(AverageGfxActivity), 64);
EQ(M3(AverageUclkActivity), 66); EQ(M3(AverageSocketPower), 72);
EQ(M3(TemperatureEdge), 74); EQ(M3(TemperatureHotspot), 76); EQ(M3(TemperatureMem), 78);
EQ(M3(TemperatureVrGfx), 80); EQ(M3(TemperatureVrSoc), 86);
EQ(M3(ThrottlingPercentage), 100); EQ(M3(CurrFanSpeed), 122); EQ(M3(PcieRate), 152);
EQ(M2(CurrFanSpeed), 122); EQ(M2(PcieRate), 150); EQ(M2(PcieWidth), 151);
EQ(THROTTLER_TEMP_EDGE_BIT, 1); EQ(THROTTLER_PPT0_BIT, 13); EQ(THROTTLER_APCC_BIT, 19);
/* Board limits. */
EQ(P(FeaturesToRun), 4); EQ(P(SocketPowerLimitAc), 12); EQ(PPT_THROTTLER_PPT0, 0);
EQ(P(TemperatureLimit), 52); EQ(TEMP_EDGE, 0); EQ(TEMP_HOTSPOT, 1); EQ(TEMP_MEM, 2);
EQ(P(FanMaximumRpm), 1018);
EQ(PB(FanMaximumRpm), 1018); EQ(PB(TemperatureLimit), 52);
EQ(PB(SocketPowerLimitAc), 12); EQ(PB(FeaturesToRun), 4);
EQ(FEATURE_PPT_BIT, 24); EQ(FEATURE_ACDC_BIT, 28); EQ(FEATURE_FAN_CONTROL_BIT, 32);
EQ(FEATURE_GFXOFF_BIT, 20); EQ(FEATURE_BACO_BIT, 21);
EQ(FEATURE_DPM_UCLK_BIT, 3); EQ(FEATURE_DPM_FCLK_BIT, 4);
EQ(FEATURE_DS_GFXCLK_BIT, 12); EQ(FEATURE_DS_UCLK_BIT, 17); EQ(FEATURE_GFX_ULV_BIT, 18);
EQ(FEATURE_MMHUB_PG_BIT, 40); EQ(FEATURE_ATHUB_PG_BIT, 41);
EQ(SMU_11_0_7_PP_PLATFORM_CAP_HARDWAREDC, 0x4);
/* PPSMC messages used by telemetry, thermal and reset. */
EQ(PPSMC_MSG_TransferTableSmu2Dram, 0x12); EQ(PPSMC_MSG_TransferTableDram2Smu, 0x13);
EQ(PPSMC_MSG_GetPptLimit, 0x33); EQ(PPSMC_MSG_ReenableAcDcInterrupt, 0x34);
EQ(PPSMC_MSG_Mode1Reset, 0x30);
int main(void) { return 0; }
