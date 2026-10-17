/* Host stand-ins for the kernel pieces the extracted MST codec uses. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/types.h>
#include <drm/display/drm_dp.h>
typedef struct { u8 b[16]; } guid_t;
#define import_guid(dst, src) memcpy((dst), (src), 16)
struct list_head { void *next, *prev; };
struct drm_dp_mst_branch { u8 rad[8]; u8 lct; };
struct drm_dp_mst_topology_mgr { int max_dpcd_transaction_bytes; void *dev; };
struct drm_printer { int unused; };
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define min3(a, b, c) min(min(a, b), c)
#define BIT(n) (1UL << (n))
#define GENMASK(h, l) (((~0UL) << (l)) & (~0UL >> (sizeof(long) * 8 - 1 - (h))))
#define FIELD_PREP(m, v) (((v) << __builtin_ctzl(m)) & (m))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define DIV_ROUND_UP_ULL(n, d) (((unsigned long long)(n) + (d) - 1) / (d))
#define DIV64_U64_ROUND_UP(n, d) (((unsigned long long)(n) + (d) - 1) / (d))
#define ALIGN(x, a) (((x) + (a) - 1) / (a) * (a))
#define mul_u32_u32(a, b) ((unsigned long long)(u32)(a) * (u32)(b))
#define WARN_ON(x) (x)
#define FXP_Q4_FMT "%d"
#define FXP_Q4_ARGS(x) (x)
#define DRM_DP_BW_OVERHEAD_MST BIT(0)
#define DRM_DP_BW_OVERHEAD_UHBR BIT(1)
#define DRM_DP_BW_OVERHEAD_SSC_REF_CLK BIT(2)
#define DRM_DP_BW_OVERHEAD_FEC BIT(3)
#define DRM_DP_BW_OVERHEAD_DSC BIT(4)
#define DRM_DEBUG_KMS(...) ((void)0)
#define drm_dbg_kms(...) ((void)0)
#define drm_err(...) ((void)0)
#define print_hex_dump(...) ((void)0)
#define drm_debug_enabled(x) 0
#define drm_dbg_printer(...) ((struct drm_printer){0})
#define drm_printf(...) ((void)0)
#define drm_dp_mst_dump_sideband_msg_tx(...) ((void)0)
#define drm_dp_mst_req_type_str(x) ""
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_FOR_TESTS_ONLY(x)
#define U16_MAX 0xffff
static int drm_dp_send_sideband_msg(struct drm_dp_mst_topology_mgr *mgr, bool up, u8 *msg, int len);
