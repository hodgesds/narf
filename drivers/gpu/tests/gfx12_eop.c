/* Independent Linux header checks for the native EOP packet and IRQ controls.
 * cc -Wall -Wextra -I/usr/src/linux/drivers/gpu/drm/amd/include \
 *    -I/usr/src/linux/drivers/gpu/drm/amd/amdgpu \
 *    drivers/gpu/tests/gfx12_eop.c -o /tmp/narf-gfx12-eop
 */
#include "nvd.h"
#include "soc24_enum.h"
#include "soc15_ih_clientid.h"
#include "ivsrcid/gfx/irqsrcs_gfx_12_0_0.h"
#include "asic_reg/gc/gc_12_0_0_offset.h"
#include "asic_reg/gc/gc_12_0_0_sh_mask.h"
#define EQ(name, value) _Static_assert((unsigned)(name) == (unsigned)(value), #name)
EQ(PACKET3(PACKET3_RELEASE_MEM, 6), 0xc0064900u);
EQ(PACKET3_RELEASE_MEM_GCR_SEQ | PACKET3_RELEASE_MEM_GCR_GL2_WB |
   PACKET3_RELEASE_MEM_CACHE_POLICY(3) |
   PACKET3_RELEASE_MEM_EVENT_TYPE(CACHE_FLUSH_AND_INV_TS_EVENT) |
   PACKET3_RELEASE_MEM_EVENT_INDEX(5), 0x06600514u);
EQ(PACKET3_RELEASE_MEM_DATA_SEL(1) | PACKET3_RELEASE_MEM_INT_SEL(2), 0x22000000u);
EQ(PACKET3(PACKET3_NOP, 246), 0xc0f61000u);
EQ(regCP_INT_CNTL_RING0, 0x1e0a);
EQ(regCP_INT_CNTL_RING0_BASE_IDX, 0);
EQ(regCP_ME1_PIPE0_INT_CNTL, 0x1e25);
EQ(regCP_ME1_PIPE0_INT_CNTL_BASE_IDX, 0);
EQ(CP_INT_CNTL_RING0__TIME_STAMP_INT_ENABLE_MASK |
   CP_INT_CNTL_RING0__GENERIC0_INT_ENABLE_MASK, 0x84000000u);
EQ(CP_ME1_PIPE0_INT_CNTL__TIME_STAMP_INT_ENABLE_MASK |
   CP_ME1_PIPE0_INT_CNTL__GENERIC0_INT_ENABLE_MASK, 0x84000000u);
EQ(SOC21_IH_CLIENTID_GFX, 0x0a);
EQ(GFX_12_0_0__SRCID__CP_EOP_INTERRUPT, 181);
int main(void) { return 0; }
