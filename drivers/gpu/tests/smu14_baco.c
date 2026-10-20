/* Independent Linux SMU14.0.2 BACO/BAMACO checks for the Navi48 runtime PM.
 * cc -Wall -Wextra -Werror '-D__counted_by(x)=' \
 * -I/usr/src/linux/drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if \
 * -I/usr/src/linux/drivers/gpu/drm/amd/pm/swsmu/inc \
 * -I/usr/src/linux/drivers/gpu/drm/amd/include \
 * drivers/gpu/tests/smu14_baco.c -o /tmp/narf-smu14-baco
 *
 * amdgpu_smu.h (enum smu_baco_seq), amdgpu_dpm.h (BACO_SUPPORT/MACO_SUPPORT) and
 * amdgpu.h (enum amdgpu_runpm_mode) pull in the whole kernel, so their
 * values are copied below and must match:
 *   enum smu_baco_seq { BACO_SEQ_BACO = 0, BACO_SEQ_MSR, BACO_SEQ_BAMACO,
 *                       BACO_SEQ_ULPS, BACO_SEQ_COUNT };
 *   #define BACO_SUPPORT (1 << 0)
 *   #define MACO_SUPPORT (1 << 1)
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "atomfirmware.h"
#include "smu14_driver_if_v14_0.h"
#include "smu_v14_0_2_ppsmc.h"
#include "smu_v14_0_2_pptable.h"
#define EQ(a,b) _Static_assert((unsigned)(a) == (unsigned)(b), #a)

/* amdgpu_smu_navi48.rs MSG_ENTER_BACO / MSG_EXIT_BACO / MSG_ARM_D3. */
EQ(PPSMC_MSG_EnterBaco, 0x15);
EQ(PPSMC_MSG_ExitBaco, 0x16);
EQ(PPSMC_MSG_ArmD3, 0x17);
/* FEATURE_BACO, now in the allowed mask. */
EQ(FEATURE_BACO_BIT, 19);
/* PLATFORM_CAPS / PLATFORM_CAP_BACO / PLATFORM_CAP_MACO. */
EQ(offsetof(struct smu_14_0_2_powerplay_table, platform_caps), 32);
EQ(SMU_14_0_2_PP_PLATFORM_CAP_BACO, 0x8);
EQ(SMU_14_0_2_PP_PLATFORM_CAP_MACO, 0x10);
/* The combo table the board read transfers (COMBO_BYTES). */
EQ(sizeof(struct smu_14_0_2_powerplay_table), 5812);

int main(void) { return 0; }
