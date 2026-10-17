/* Independent Linux-header ABI check for amdgpu_mes12.rs. Run with:
 * cc -Wall -Wextra -I/usr/src/linux/drivers/gpu/drm/amd/include \
 *    drivers/gpu/tests/mes12_layout.c -o /tmp/narf-mes12-layout-check
 * /tmp/narf-mes12-layout-check
 */
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include "mes_v12_api_def.h"
#include "v12_structs.h"

#define WORD(type, member, index) \
    _Static_assert(offsetof(type, member) == 4 * (index), #type "." #member)
_Static_assert(sizeof(union MESAPI_SET_HW_RESOURCES) == 256, "resource frame");
_Static_assert(sizeof(union MESAPI__ADD_QUEUE) == 256, "add frame");
_Static_assert(sizeof(union MESAPI__REMOVE_QUEUE) == 256, "remove frame");
_Static_assert(sizeof(struct v12_compute_mqd) == 2048, "MES descriptor");
_Static_assert(sizeof(struct v12_gfx_mqd) == 2048, "graphics descriptor");
WORD(union MESAPI_SET_HW_RESOURCES, api_status, 50);
WORD(union MESAPI_SET_HW_RESOURCES, uint32_all, 54);
WORD(union MESAPI_SET_HW_RESOURCES, oversubscription_timer, 55);
WORD(union MESAPI_SET_HW_RESOURCES_1, api_status, 2);
WORD(union MESAPI_SET_HW_RESOURCES_1, mes_kiq_unmap_timeout, 13);
WORD(union MESAPI_SET_HW_RESOURCES_1, cleaner_shader_fence_mc_addr, 16);
WORD(union MESAPI__ADD_QUEUE, mqd_addr, 20);
WORD(union MESAPI__ADD_QUEUE, wptr_addr, 22);
WORD(union MESAPI__ADD_QUEUE, queue_type, 28);
WORD(union MESAPI__ADD_QUEUE, api_status, 38);
WORD(union MESAPI__ADD_QUEUE, pipe_id, 50);
WORD(union MESAPI__ADD_QUEUE, queue_id, 51);
WORD(union MESAPI__REMOVE_QUEUE, api_status, 6);
WORD(union MESAPI__REMOVE_QUEUE, pipe_id, 10);
WORD(union MESAPI__REMOVE_QUEUE, queue_type, 15);
WORD(union MESAPI__QUERY_MES_STATUS, api_status, 2);
WORD(struct v12_compute_mqd, cp_mqd_base_addr_lo, 128);
WORD(struct v12_compute_mqd, cp_hqd_pq_control, 145);
WORD(struct v12_compute_mqd, cp_mqd_control, 162);
WORD(struct v12_compute_mqd, cp_hqd_eop_base_addr_lo, 165);
WORD(struct v12_compute_mqd, reserved_184, 184);
WORD(struct v12_gfx_mqd, cp_mqd_base_addr, 128);
WORD(struct v12_gfx_mqd, cp_gfx_hqd_active, 130);
WORD(struct v12_gfx_mqd, cp_gfx_hqd_quantum, 135);
WORD(struct v12_gfx_mqd, cp_gfx_hqd_base, 136);
WORD(struct v12_gfx_mqd, cp_gfx_hqd_rptr_addr, 139);
WORD(struct v12_gfx_mqd, cp_rb_wptr_poll_addr_lo, 141);
WORD(struct v12_gfx_mqd, cp_rb_doorbell_control, 143);
WORD(struct v12_gfx_mqd, cp_gfx_hqd_cntl, 145);
WORD(struct v12_gfx_mqd, cp_gfx_mqd_control, 162);

int main(void)
{
    union MESAPI__ADD_QUEUE add = {0};
    union MESAPI__REMOVE_QUEUE remove = {0};
    union MESAPI_SET_HW_RESOURCES resources = {0};
    add.map_legacy_kq = 1;
    remove.unmap_legacy_queue = 1;
    resources.disable_reset = 1;
    resources.disable_mes_log = 1;
    resources.use_different_vmid_compute = 1;
    resources.enable_reg_active_poll = 1;
    resources.enable_level_process_quantum_check = 1;
    resources.unmapped_doorbell_handling = 2;
    assert(add.max_dwords_in_api[37] == 0x2000);
    assert(remove.max_dwords_in_api[4] == 8);
    assert(resources.max_dwords_in_api[54] == 0x100447);
    return 0;
}
