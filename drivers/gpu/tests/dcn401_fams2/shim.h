/* The DC types dc_dmub_srv_rb_based_fams2_update_config reads, reduced to
 * the fields it touches (dc.h, core_types.h, dc_state), and the DMUB
 * command list sink it posts to. The DMUB command layouts are the real
 * dmub_cmd.h. */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "dmub_cmd.h"

#define MAX_STREAMS 6 /* dc.h */
#define DML2_MAX_PLANES 8 /* dml_top_display_cfg_types.h */

enum visual_confirm { VISUAL_CONFIRM_DISABLE = 0, VISUAL_CONFIRM_FAMS2 = 19 };
enum dm_dmub_wait_type { DM_DMUB_WAIT_TYPE_NO_WAIT, DM_DMUB_WAIT_TYPE_WAIT };

struct dc_context {
	int unused;
};
struct dc_debug_options {
	enum visual_confirm visual_confirm;
	union dmub_fams2_global_feature_config fams2_config;
};
struct dc {
	struct dc_context *ctx;
	struct dc_debug_options debug;
};
struct dc_state {
	struct {
		struct {
			struct {
				struct dmub_cmd_fams2_global_config fams2_global_config;
				union dmub_cmd_fams2_config fams2_stream_base_params[DML2_MAX_PLANES];
				union dmub_cmd_fams2_config fams2_stream_sub_params[DML2_MAX_PLANES];
			} dcn;
		} bw;
	} bw_ctx;
};

bool dm_execute_dmub_cmd_list(const struct dc_context *ctx, unsigned int count,
			      union dmub_rb_cmd *cmd, enum dm_dmub_wait_type wait_type);
