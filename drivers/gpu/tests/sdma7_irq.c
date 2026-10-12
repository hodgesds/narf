/* Independent Linux SDMA7 packet, source and register definitions.
 * cc -Wall -Wextra -Werror -I/usr/src/linux/drivers/gpu/drm/amd/include \
 *    -I/usr/src/linux/drivers/gpu/drm/amd/amdgpu \
 *    drivers/gpu/tests/sdma7_irq.c -o /tmp/narf-sdma7-irq
 */
#include "sdma_v6_0_0_pkt_open.h"
#include "soc15_ih_clientid.h"
#include "ivsrcid/gfx/irqsrcs_gfx_12_0_0.h"
#include "asic_reg/gc/gc_12_0_0_offset.h"
#include "asic_reg/gc/gc_12_0_0_sh_mask.h"
#define EQ(a, b) _Static_assert((unsigned)(a) == (unsigned)(b), #a)
EQ(SDMA_PKT_COPY_LINEAR_HEADER_OP(SDMA_OP_FENCE) | SDMA_PKT_FENCE_HEADER_MTYPE(3), 0x30005);
EQ(SDMA_PKT_COPY_LINEAR_HEADER_OP(SDMA_OP_TRAP), 6);
EQ(SDMA_PKT_TRAP_INT_CONTEXT_INT_CONTEXT(0), 0);
EQ(regSDMA0_CNTL, 0x0d);
EQ(regSDMA0_CNTL_BASE_IDX, 0);
EQ(SDMA0_CNTL__TRAP_ENABLE_MASK, 1);
EQ(regSDMA0_QUEUE0_RB_RPTR, 0x83);
EQ(regSDMA0_QUEUE0_RB_RPTR_HI, 0x84);
EQ(regSDMA0_QUEUE0_RB_WPTR, 0x85);
EQ(regSDMA0_QUEUE0_RB_WPTR_HI, 0x86);
EQ(SOC21_IH_CLIENTID_GFX, 0x0a);
EQ(GFX_12_0_0__SRCID__SDMA_TRAP, 49);
EQ(GFX_12_0_0__SRCID__SDMA_FENCE, 70);
int main(void) { return 0; }
