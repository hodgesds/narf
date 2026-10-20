/* Independent Linux definitions behind amdgpu_navi48_ras and the Navi48
 * poison/ECC source table.
 * cc -Wall -Wextra -Werror -D'__counted_by(x)=' \
 *    -I/usr/src/linux/drivers/gpu/drm/amd/include \
 *    -I/usr/src/linux/drivers/gpu/drm/amd/amdgpu \
 *    drivers/gpu/tests/navi48_ras.c -o /tmp/narf-navi48-ras && /tmp/narf-navi48-ras
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "atomfirmware.h"
#include "ta_ras_if.h"
#include "soc15_ih_clientid.h"
#include "ivsrcid/gfx/irqsrcs_gfx_12_0_0.h"
#include "ivsrcid/vcn/irqsrcs_vcn_5_0.h"
#include "ivsrcid/nbio/irqsrcs_nbif_7_4.h"
#include "asic_reg/umc/umc_8_14_0_offset.h"
#include "asic_reg/umc/umc_8_14_0_sh_mask.h"
#include "asic_reg/nbif/nbif_6_3_1_offset.h"
#include "asic_reg/nbif/nbif_6_3_1_sh_mask.h"
#define EQ(a, b) _Static_assert((unsigned long)(a) == (unsigned long)(b), #a)
#define AT(s, f, o) EQ(offsetof(struct s, f), o)

/* VBIOS capability bits (amdgpu_atomfirmware_mem_ecc_supported and
 * amdgpu_atomfirmware_query_firmware_capability). */
EQ(offsetof(struct atom_master_list_of_data_tables_v2_1, firmwareinfo) / 2, 4);
EQ(offsetof(struct atom_master_list_of_data_tables_v2_1, umc_info) / 2, 24);
AT(atom_firmware_info_v3_1, firmware_capability, 0x10);
EQ(ATOM_FIRMWARE_CAP_SRAM_ECC, 0x200);
AT(atom_umc_info_v3_1, umc_config, 27);
AT(atom_umc_info_v3_2, umc_config, 27);
AT(atom_umc_info_v3_3, umc_config, 27);
AT(atom_umc_info_v3_3, umc_config1, 52);
AT(atom_umc_info_v4_0, umc_config, 27);
AT(atom_umc_info_v4_0, umc_config1, 52);
EQ(UMC_CONFIG__DEFAULT_MEM_ECC_ENABLE, 0x02);
EQ(UMC_CONFIG1__ENABLE_ECC_CAPABLE, 0x10000);

/* amdgpu_ras_block, mirrored one-to-one by amdgpu_ras_block_to_ta. */
EQ(TA_RAS_BLOCK__UMC, 0);
EQ(TA_RAS_BLOCK__SDMA, 1);
EQ(TA_RAS_BLOCK__GFX, 2);
EQ(TA_RAS_BLOCK__MMHUB, 3);
EQ(TA_RAS_BLOCK__ATHUB, 4);
EQ(TA_RAS_BLOCK__PCIE_BIF, 5);
EQ(TA_RAS_BLOCK__HDP, 6);
EQ(TA_RAS_BLOCK__XGMI_WAFL, 7);
EQ(TA_RAS_BLOCK__DF, 8);
EQ(TA_RAS_BLOCK__VCN, 15);
EQ(TA_RAS_BLOCK__JPEG, 16);
EQ(TA_RAS_BLOCK__MMSCH, 19);
EQ(TA_NUM_BLOCK_MAX, 20);

/* UMC 8.14 channel counters (umc_v8_14.c / umc_v8_14.h values). */
EQ(regUMCCH0_GeccErrCntSel, 0x328);
EQ(regUMCCH0_GeccErrCntSel_BASE_IDX, 0);
EQ(regUMCCH0_GeccErrCnt, 0x329);
EQ(regUMCCH0_GeccErrCnt_BASE_IDX, 0);
EQ(UMCCH0_GeccErrCntSel__GeccErrInt_MASK, 0x3000);
EQ(1 << UMCCH0_GeccErrCntSel__GeccErrInt__SHIFT, 0x1000);
EQ(UMCCH0_GeccErrCnt__GeccErrCnt_MASK, 0xffff);
EQ(UMCCH0_GeccErrCnt__GeccUnCorrErrCnt_MASK, 0xffff0000);
EQ(UMCCH0_GeccErrCnt__GeccUnCorrErrCnt__SHIFT, 16);

/* NBIF 6.3.1: RSMU indirect pair and the ATHUB error-event control. */
EQ(regBIF_BX_PF0_RSMU_INDEX, 0);
EQ(regBIF_BX_PF0_RSMU_INDEX_BASE_IDX, 1);
EQ(regBIF_BX_PF0_RSMU_DATA, 1);
EQ(regBIF_BX_PF0_RSMU_DATA_BASE_IDX, 1);
EQ(regBIF_BX0_BIF_DOORBELL_INT_CNTL, 0xfe);
EQ(regBIF_BX0_BIF_DOORBELL_INT_CNTL_BASE_IDX, 2);
EQ(BIF_BX0_BIF_DOORBELL_INT_CNTL__RAS_ATHUB_ERR_EVENT_INTERRUPT_STATUS_MASK, 1 << 2);
EQ(BIF_BX0_BIF_DOORBELL_INT_CNTL__RAS_ATHUB_ERR_EVENT_INTERRUPT_CLEAR_MASK, 1 << 18);
EQ(BIF_BX0_BIF_DOORBELL_INT_CNTL__RAS_ATHUB_ERR_EVENT_INTERRUPT_DISABLE_MASK, 1 << 26);

/* Poison/ECC sources amdgpu_navi48_sources decodes. */
EQ(SOC21_IH_CLIENTID_GFX, 0x0a);
EQ(SOC21_IH_CLIENTID_DF, 0x17);
EQ(SOC21_IH_CLIENTID_BIF, 0x03);
EQ(SOC15_IH_CLIENTID_VCN, 0x10);
EQ(SOC15_IH_CLIENTID_VCN1, 0x0e);
EQ(GFX_12_0_0__SRCID__UTCL2_DATA_POISONING, 1);
EQ(GFX_12_0_0__SRCID__SDMA_TRAP, 49);
EQ(GFX_12_0_0__SRCID__SDMA_ECC, 62);
EQ(GFX_12_0_0__SRCID__SDMA_SRAM_ECC, 64);
EQ(GFX_12_0_0__SRCID__SDMA_FENCE, 70);
EQ(GFX_12_0_0__SRCID__RLC_GC_FED_INTERRUPT, 128);
EQ(GFX_12_0_0__SRCID__CP_ECC_ERROR, 197);
EQ(GFX_12_0_0__SRCID__CP_FUE_ERROR, 201);
EQ(GFX_12_0_0__SRCID__SQ_INTERRUPT_ID, 239);
EQ(VCN_5_0__SRCID__UVD_ENC_GENERAL_PURPOSE, 119);
EQ(VCN_5_0__SRCID__JPEG_DECODE, 153);
EQ(VCN_5_0__SRCID_UVD_POISON, 160);
EQ(VCN_5_0__SRCID_DJPEG0_POISON, 161);
EQ(VCN_5_0__SRCID_EJPEG0_POISON, 162);
EQ(NBIF_7_4__SRCID__ERREVENT_ATHUB_INTERRUPT, 0x61);

/* amdgpu_ras_query_ras_capablity_from_vbios + amdgpu_ras_check_supported for
 * bare-metal Navi48 (VCN 5.0.0, no XGMI), expressions copied verbatim. */
#define AMDGPU_RAS_BLOCK__UMC TA_RAS_BLOCK__UMC
#define AMDGPU_RAS_BLOCK__DF TA_RAS_BLOCK__DF
#define AMDGPU_RAS_BLOCK__VCN TA_RAS_BLOCK__VCN
#define AMDGPU_RAS_BLOCK__JPEG TA_RAS_BLOCK__JPEG
#define AMDGPU_RAS_BLOCK__XGMI_WAFL TA_RAS_BLOCK__XGMI_WAFL
#define AMDGPU_RAS_BLOCK_MASK ((1ULL << TA_NUM_BLOCK_MAX) - 1)
static unsigned hw_enabled(int mem_ecc, int sram_ecc)
{
	unsigned ras_hw_enabled = 0;
	if (mem_ecc)
		ras_hw_enabled |= (1 << AMDGPU_RAS_BLOCK__UMC |
				   1 << AMDGPU_RAS_BLOCK__DF);
	if (sram_ecc) {
		ras_hw_enabled |= ~(1 << AMDGPU_RAS_BLOCK__UMC |
				    1 << AMDGPU_RAS_BLOCK__DF);
		ras_hw_enabled &= ~(1 << AMDGPU_RAS_BLOCK__VCN |
				    1 << AMDGPU_RAS_BLOCK__JPEG);
		ras_hw_enabled &= ~(1 << AMDGPU_RAS_BLOCK__XGMI_WAFL);
	}
	ras_hw_enabled &= AMDGPU_RAS_BLOCK_MASK;
	return ras_hw_enabled;
}
int main(void)
{
	/* The same vectors navi48_ras_block_mask_matches_linux_check_supported uses. */
	static const unsigned expect[4] = { 0, 0x101, 0xe7e7e, 0xe7f7f };
	int bad = 0;
	for (int i = 0; i < 4; i++) {
		unsigned got = hw_enabled(i & 1, i >> 1);
		if (got != expect[i]) {
			printf("mem=%d sram=%d: %#x != %#x\n", i & 1, i >> 1, got, expect[i]);
			bad = 1;
		}
	}
	return bad;
}
