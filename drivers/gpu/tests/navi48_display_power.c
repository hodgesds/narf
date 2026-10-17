/* cc -Wall -Wextra -Werror \
 * -I/usr/src/linux/drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if \
 * drivers/gpu/tests/navi48_display_power.c -o /tmp/narf-navi48-display-power
 */
#include <stdint.h>
#include <stdbool.h>
#include "smu14_driver_if_v14_0.h"
#include "smu_v14_0_2_ppsmc.h"
#define EQ(a,b) _Static_assert((unsigned)(a) == (unsigned)(b), #a)
EQ((1 << FEATURE_DPM_UCLK_BIT) | (1 << FEATURE_DPM_FCLK_BIT) |
   (1 << FEATURE_DPM_SOCCLK_BIT) | (1 << FEATURE_DPM_DCN_BIT), 0xb8);
EQ(PPSMC_MSG_SetAllowedFeaturesMaskLow, 4);
EQ(PPSMC_MSG_SetAllowedFeaturesMaskHigh, 5);
EQ(PPSMC_MSG_EnableAllSmuFeatures, 6);
EQ(PPSMC_MSG_GetRunningSmuFeaturesLow, 12);
EQ(PPSMC_MSG_GetRunningSmuFeaturesHigh, 13);
EQ(NUM_UCLK_DPM_LEVELS, 6); EQ(NUM_FCLK_DPM_LEVELS, 8); EQ(NUM_SOCCLK_DPM_LEVELS, 8);
EQ(NUM_DISPCLK_DPM_LEVELS, 8); EQ(NUM_DPPCLK_DPM_LEVELS, 8);
EQ(NUM_DCFCLK_DPM_LEVELS, 8); EQ(NUM_DTBCLK_DPM_LEVELS, 8);
int main(void) { return 0; }
