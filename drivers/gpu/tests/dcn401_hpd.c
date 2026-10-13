/* Native HPD sense contract, independent of the Rust MMIO model.
 * cc -Wall -Wextra -Werror -I/usr/src/linux/drivers/gpu/drm/amd/include \
 *    drivers/gpu/tests/dcn401_hpd.c -o /tmp/narf-dcn401-hpd
 */
#include "asic_reg/dcn/dcn_4_1_0_offset.h"
#include "asic_reg/dcn/dcn_4_1_0_sh_mask.h"
#define EQ(a,b) _Static_assert((unsigned)(a) == (unsigned)(b), #a)
#define R(a,b,bank) EQ(reg##a,b); EQ(reg##a##_BASE_IDX,bank)
#define BLOCK(i) \
 R(HPD##i##_DC_HPD_INT_STATUS, 0x175a + 8*(i), 2); \
 R(HPD##i##_DC_HPD_CONTROL, 0x175c + 8*(i), 2)
BLOCK(0); BLOCK(1); BLOCK(2); BLOCK(3);
/* Four blocks: HPD4 is not instantiated on DCN 4.1. */
#ifdef regHPD4_DC_HPD_INT_STATUS
#error "DCN401 has a fifth HPD block"
#endif
EQ(HPD0_DC_HPD_INT_STATUS__DC_HPD_SENSE_DELAYED_MASK, 0x10);
EQ(HPD0_DC_HPD_CONTROL__DC_HPD_EN_MASK, 0x10000000);
R(DC_GPIO_HPD_MASK, 0x28f4, 2);
/* GPIO_HPD_1..4 pad masks, cleared for interrupt (HPD block) mode. */
EQ(DC_GPIO_HPD_MASK__DC_GPIO_HPD1_MASK_MASK, 0x1);
EQ(DC_GPIO_HPD_MASK__DC_GPIO_HPD2_MASK_MASK, 0x100);
EQ(DC_GPIO_HPD_MASK__DC_GPIO_HPD3_MASK_MASK, 0x10000);
EQ(DC_GPIO_HPD_MASK__DC_GPIO_HPD4_MASK_MASK, 0x100000);
int main(void) { return 0; }
