/* Independent NBIO and native ring HDP handshake definitions.
 * Compile with both NBIO7.7 (default) and -DNARF_NBIF for NBIF6.3.1:
 * cc -Wall -Wextra -Werror -I/usr/src/linux/drivers/gpu/drm/amd/include \
 *    -I/usr/src/linux/drivers/gpu/drm/amd/amdgpu \
 *    drivers/gpu/tests/navi48_hdp.c -o /tmp/narf-navi48-hdp
 */
#include "nvd.h"
#include "sdma_v6_0_0_pkt_open.h"
#ifdef NARF_NBIF
#include "asic_reg/nbif/nbif_6_3_1_offset.h"
#include "asic_reg/nbif/nbif_6_3_1_sh_mask.h"
#else
#include "asic_reg/nbio/nbio_7_7_0_offset.h"
#include "asic_reg/nbio/nbio_7_7_0_sh_mask.h"
#endif
#define EQ(a, b) _Static_assert((unsigned)(a) == (unsigned)(b), #a)
EQ(regBIF_BX_PF0_GPU_HDP_FLUSH_REQ, 0x106);
EQ(regBIF_BX_PF0_GPU_HDP_FLUSH_REQ_BASE_IDX, 2);
EQ(regBIF_BX_PF0_GPU_HDP_FLUSH_DONE, 0x107);
EQ(regBIF_BX_PF0_GPU_HDP_FLUSH_DONE_BASE_IDX, 2);
EQ(BIF_BX_PF0_GPU_HDP_FLUSH_DONE__CP0_MASK, 1);
EQ(BIF_BX_PF0_GPU_HDP_FLUSH_DONE__CP2_MASK, 4);
EQ(BIF_BX_PF0_GPU_HDP_FLUSH_DONE__SDMA0_MASK, 0x400);
EQ(PACKET3(PACKET3_WAIT_REG_MEM, 5), 0xc0053c00);
EQ(WAIT_REG_MEM_OPERATION(1) | WAIT_REG_MEM_FUNCTION(3), 0x43);
EQ(WAIT_REG_MEM_OPERATION(1) | WAIT_REG_MEM_FUNCTION(3) |
   WAIT_REG_MEM_ENGINE(1), 0x143);
EQ(SDMA_PKT_COPY_LINEAR_HEADER_OP(SDMA_OP_POLL_REGMEM) |
   SDMA_PKT_POLL_REGMEM_HEADER_HDP_FLUSH(1) |
   SDMA_PKT_POLL_REGMEM_HEADER_FUNC(3), 0x34000008);
EQ(SDMA_PKT_POLL_REGMEM_DW5_RETRY_COUNT(0xfff) |
   SDMA_PKT_POLL_REGMEM_DW5_INTERVAL(10), 0x0fff000a);
int main(void) { return 0; }
