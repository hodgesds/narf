/* Independent Linux-header check for the shared reset core's Navi48 profile.
 * cc -Wall -Wextra -Werror -I/usr/src/linux/drivers/gpu/drm/amd/include \
 *   drivers/gpu/tests/reset_navi48_layout.c -o /tmp/narf-reset-navi48-layout
 */
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#define __counted_by(member)
#include "atomfirmware.h"
#include "asic_reg/mp/mp_14_0_2_offset.h"
#include "asic_reg/nbio/nbio_7_11_0_offset.h"
_Static_assert(regMP1_SMN_C2PMSG_53 == 0x75 && regMP1_SMN_C2PMSG_53_BASE_IDX == 1, "debug parameter");
_Static_assert(regMP1_SMN_C2PMSG_75 == 0x8b && regMP1_SMN_C2PMSG_75_BASE_IDX == 1, "debug command");
_Static_assert(regMP1_SMN_C2PMSG_54 == 0x76 && regMP1_SMN_C2PMSG_54_BASE_IDX == 1, "debug response");
_Static_assert(regBIF_BX1_PCIE_INDEX2 == 0xe && regBIF_BX1_PCIE_DATA2 == 0xf, "indirect registers");
_Static_assert(regBIF_BX1_PCIE_DATA2_BASE_IDX == 0, "indirect base");
_Static_assert(regRCC_DEV0_EPF0_0_RCC_CONFIG_MEMSIZE == 0xc3, "memory size");
_Static_assert(regRCC_DEV0_EPF0_0_RCC_CONFIG_MEMSIZE_BASE_IDX == 2, "memory size base");
_Static_assert(sizeof(struct asic_init_ps_allocation_v2_1) == 72, "ASIC_Init v2.1 workspace");
_Static_assert(b3NORMAL_ENGINE_INIT == 0 && b3NORMAL_MEM_INIT == 0, "normal post flags");
int main(void) {
    union { struct asic_init_ps_allocation_v2_1 p; uint32_t d[18]; } v = {0};
    v.p.param.engineparam.sclkfreqin10khz = 0x123456;
    v.p.param.memparam.mclkfreqin10khz = 0x654321;
    assert(v.d[0] == 0x123456 && v.d[1] == 0x654321);
    for (unsigned i = 2; i < 18; ++i) assert(v.d[i] == 0);
    return 0;
}
