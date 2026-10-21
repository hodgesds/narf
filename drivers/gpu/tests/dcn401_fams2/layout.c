/* Independent Linux DCN401 FAMS2, DMUB inbox0 lock and DALSMC P-state checks
 * for amdgpu_dmub_navi48.rs and amdgpu_dcn401_clk.rs: the layouts as static
 * asserts against the DMUB, DALSMC and DCN 4.1 headers, the inbox0 lock words
 * and feature bits at run time. check.sh builds and runs it; harness.c
 * checks the FAMS2_CONFIG bytes themselves.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "dmub_cmd.h"
#include "dalsmc.h"
#include "dcn401_smu14_driver_if.h"
#include "asic_reg/dcn/dcn_4_1_0_offset.h"
#define EQ(a, b) _Static_assert((unsigned long)(a) == (unsigned long)(b), #a)
#define B(f) offsetof(struct dmub_fams2_cmd_stream_static_base_state, f)
#define G(f) offsetof(struct dmub_cmd_fams2_global_config, f)

/* FAMS2_CONFIG commands: one 64-byte ring slot each, 60 payload bytes. */
EQ(DMUB_CMD__FW_ASSISTED_MCLK_SWITCH, 76);
EQ(DMUB_CMD__FAMS2_CONFIG, 4);
EQ(sizeof(struct dmub_rb_cmd_fams2), 64);
EQ(sizeof(struct dmub_rb_cmd_fams2) - sizeof(struct dmub_cmd_header), 60);
EQ(offsetof(struct dmub_rb_cmd_fams2, config), 4);
EQ(sizeof(struct dmub_cmd_fams2_global_config), 28);
EQ(G(max_allow_delay_us), 0); EQ(G(lock_wait_time_us), 4); EQ(G(num_streams), 8);
EQ(G(features), 12); EQ(G(recovery_timeout_us), 16);
EQ(G(hwfq_flip_programming_delay_us), 20); EQ(G(max_allow_to_target_delta_us), 24);
EQ(B(type), 0); EQ(B(otg_vline_time_ns), 4); EQ(B(otg_vline_time_ticks), 8);
EQ(B(htotal), 12); EQ(B(vtotal), 14); EQ(B(vblank_start), 16); EQ(B(vblank_end), 18);
EQ(B(max_vtotal), 20); EQ(B(allow_start_otg_vline), 22); EQ(B(allow_end_otg_vline), 24);
EQ(B(drr_keepout_otg_vline), 26); EQ(B(scheduling_delay_otg_vlines), 28);
EQ(B(contention_delay_otg_vlines), 30); EQ(B(vline_int_ack_delay_otg_vlines), 32);
EQ(B(allow_to_target_delay_otg_vlines), 34); EQ(B(config), 36); EQ(B(otg_inst), 37);
EQ(B(pipe_mask), 38); EQ(B(num_planes), 39); EQ(B(plane_pipe_masks), 40);
EQ(DMUB_MAX_PLANES, 6);
EQ(offsetof(struct dmub_fams2_cmd_legacy_stream_static_state, vactive_det_fill_delay_otg_vlines), 0);
EQ(FAMS2_STREAM_TYPE_VBLANK, 1); EQ(FAMS2_STREAM_TYPE_VACTIVE, 2);
EQ(FAMS2_STREAM_TYPE_DRR, 3); EQ(FAMS2_STREAM_TYPE_SUBVP, 4);
EQ(FAMS2_ALLOW_DELAY_CHECK_FROM_START, 1);
/* The DMUB feature caps byte the FAMS version comes from. */
EQ(offsetof(struct dmub_feature_caps, fw_assisted_mclk_switch_ver), 1);
EQ(sizeof(struct dmub_feature_caps), 14);
/* inbox0 HW lock: DMCUB_INBOX0_WPTR, its ack in DMCUB_SCRATCH17. */
EQ(regDMCUB_INBOX0_WPTR, 0x1d2); EQ(regDMCUB_SCRATCH17, 0x1f4);
EQ(DMUB_INBOX0_CMD__HW_LOCK, 1); EQ(HW_LOCK_CLIENT_DRIVER, 0);
/* DALSMC P-state messages and the watermark range table. */
EQ(DALSMC_MSG_SetDalDramAddrHigh, 0x5); EQ(DALSMC_MSG_SetDalDramAddrLow, 0x6);
EQ(DALSMC_MSG_TransferTableDram2Smu, 0x8); EQ(DALSMC_MSG_SetMinDeepSleepDcfclk, 0xd);
EQ(DALSMC_MSG_SetAlwaysWaitDmcubResp, 0x16); EQ(DALSMC_MSG_IndicateDrrStatus, 0x17);
EQ(DALSMC_MSG_ActiveUclkFclk, 0x18); EQ(DALSMC_MSG_IdleUclkFclk, 0x19);
EQ(DALSMC_MSG_SetUclkPstateAllow, 0x1a);
EQ(TABLE_WATERMARKS, 2); EQ(PPCLK_UCLK, 2); EQ(PPCLK_FCLK, 3);
EQ(WATERMARKS_CLOCK_RANGE, 0); EQ(WATERMARKS_DUMMY_PSTATE, 1);
EQ(sizeof(WatermarksExternal_t), 112); EQ(NUM_WM_RANGES, 4);
EQ(offsetof(WatermarkRowGeneric_t, WmSetting), 0); EQ(offsetof(WatermarkRowGeneric_t, Flags), 1);
EQ(sizeof(WatermarkRowGeneric_t), 4);

int main(void)
{
	union dmub_inbox0_cmd_lock_hw lock = { 0 }, release = { 0 };
	union fw_assisted_mclk_switch_version v = { .minor = 1, .major = 2 };
	union dmub_fams2_global_feature_config f = { 0 };

	lock.bits.command_code = DMUB_INBOX0_CMD__HW_LOCK;
	lock.bits.hw_lock_client = HW_LOCK_CLIENT_DRIVER;
	lock.bits.lock = 1;
	release.bits.command_code = DMUB_INBOX0_CMD__HW_LOCK;
	release.bits.should_release = 1;
	f.bits.enable = f.bits.enable_stall_recovery = f.bits.enable_offload_flip = 1;
	f.bits.allow_delay_check_mode = FAMS2_ALLOW_DELAY_CHECK_FROM_START;
	return !(lock.all == 0x00800001 && release.all == 0x01000001 && v.ver == 0x41 &&
		 f.all == (1 | 1 << 2 | 1 << 4 | 1 << 6));
}
