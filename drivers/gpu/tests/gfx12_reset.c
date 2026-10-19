/* Linux 7.3-rc4 header contract for GC12.0.1 compute queue/pipe recovery.
 * cc -Wall -Wextra -Werror -I/usr/src/linux/drivers/gpu/drm/amd/include \
 *    drivers/gpu/tests/gfx12_reset.c -o /tmp/narf-gfx12-reset
 */
#include "asic_reg/gc/gc_12_0_0_offset.h"
#include "asic_reg/gc/gc_12_0_0_sh_mask.h"
#define EQ(name, value) _Static_assert((unsigned)(name) == (unsigned)(value), #name)
EQ(regCP_HQD_DEQUEUE_REQUEST, 0x1fc1);
EQ(regCP_HQD_DEQUEUE_REQUEST_BASE_IDX, 0);
EQ(regSPI_COMPUTE_QUEUE_RESET, 0x1f73);
EQ(regSPI_COMPUTE_QUEUE_RESET_BASE_IDX, 0);
EQ(regCP_HQD_ACTIVE, 0x1fab);
EQ(regCP_HQD_ACTIVE_BASE_IDX, 0);
EQ(regCP_MEC_RS64_CNTL, 0x2904);
EQ(regCP_MEC_RS64_CNTL_BASE_IDX, 1);
EQ(CP_MEC_RS64_CNTL__MEC_PIPE0_RESET_MASK, 0x10000);
EQ(regRLC_CNTL, 0x4c00);
EQ(regRLC_CNTL_BASE_IDX, 1);
EQ(RLC_CNTL__RLC_ENABLE_F32_MASK, 1);
EQ(regRLC_SAFE_MODE, 0x980);
EQ(regRLC_SAFE_MODE_BASE_IDX, 1);
EQ(RLC_SAFE_MODE__CMD_MASK, 1);
EQ(RLC_SAFE_MODE__MESSAGE__SHIFT, 1);
EQ(GRBM_GFX_CNTL__MEID__SHIFT, 2);
EQ(GRBM_GFX_CNTL__QUEUEID__SHIFT, 8);
int main(void) { return 0; }
