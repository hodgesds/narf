/* Linux register and PMFW layout amdgpu_rdna4 and the Navi44 paths rely on.
 * Built by check.sh; compiles only if every assertion holds.
 *
 * Both RDNA4 dies use one GC register header (gfx_v12_0.c includes only
 * gc_12_0_0_offset.h), one DCN header (dcn_4_1_0_offset.h for DCN 4.0.1)
 * and one SMU14 driver interface (smu14_driver_if_v14_0.h, used by
 * smu_v14_0_2_ppt.c for MP1 14.0.2 and 14.0.3 alike), so the Navi48 offsets
 * the driver already checks against these headers serve Navi44 unchanged.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "atomfirmware.h"
#include "smu14_driver_if_v14_0.h"
#include "smu_v14_0_2_pptable.h"
#include "gc/gc_12_0_0_offset.h"
#include "dcn/dcn_4_1_0_offset.h"
#include "dcn/dcn_4_1_0_sh_mask.h"
#define EQ(a, b) _Static_assert((unsigned long long)(a) == (unsigned long long)(b), #a)

/* amdgpu_rdna4::CC_DC_PIPE_DIS / read_display_pipes (BASE_IDX 2). */
EQ(regCC_DC_PIPE_DIS, 0x00ca);
EQ(regCC_DC_PIPE_DIS_BASE_IDX, 2);
/* read_pipe_fuses keeps four pipes' bits of DC_PIPE_DIS. */
EQ(CC_DC_PIPE_DIS__DC_PIPE_DIS_MASK & 0xf, 0xf);
EQ(CC_DC_PIPE_DIS__DC_PIPE_DIS__SHIFT, 0);

/* amdgpu_gfx12_setup::GOLDEN / GOLDEN_REV0 bank selection. */
EQ(regDB_MEM_CONFIG_BASE_IDX, 0);
EQ(regCB_HW_CONTROL_1_BASE_IDX, 0);
EQ(regGL2C_CTRL5_BASE_IDX, 1);

/* The PMFW tables amdgpu_smu_navi48 transfers, identical for both MP1s. */
EQ(sizeof(struct smu_14_0_2_powerplay_table), 5812);
EQ(sizeof(PPTable_t) <= 0x4000, 1);
EQ(sizeof(SmuMetricsExternal_t) <= 0x4000, 1);

int main(void) { return 0; }
