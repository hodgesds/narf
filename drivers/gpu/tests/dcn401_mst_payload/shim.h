/* Host stand-ins for the kernel pieces DRM's MST payload helpers use. The
 * payload and topology-state structs are extracted from
 * drm_dp_mst_helper.h by check.sh; the manager keeps only the fields the
 * extracted functions read. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define DP_PAYLOAD_TABLE_UPDATE_STATUS 0x2c0
#define DP_PAYLOAD_TABLE_UPDATED (1 << 0)
#define DP_PAYLOAD_ALLOCATE_SET 0x1c0
#define DP_CAP_ANSI_8B10B (1 << 0)
#define DP_CAP_ANSI_128B132B (1 << 1)
#define ENOSPC 28
#define EINVAL 22
#define EIO 5
#define BIT(n) (1UL << (n))
#define ffz(x) __builtin_ctzl(~(unsigned long)(x))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define div64_u64(a, b) ((a) / (b))
#define dfixed_const(A) (u32)(((A) << 12))
typedef union dfixed { u32 full; } fixed20_12;
#define drm_dbg_kms(...) ((void)0)
#define DRM_DEBUG_KMS(...) ((void)0)
#define drm_dbg_atomic(...) ((void)0)
#define drm_err(...) ((void)0)
#define EXPORT_SYMBOL(x)
#define EXPORT_IF_KUNIT(x)
#define mutex_lock(x) ((void)0)
#define mutex_unlock(x) ((void)0)
#define usleep_range(a, b) ((void)0)

struct list_head { struct list_head *next, *prev; };
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_entry(p, t, m) container_of(p, t, m)
#define list_for_each_entry(pos, head, member)                                       \
	for (pos = list_entry((head)->next, __typeof__(*pos), member); &pos->member != (head); \
	     pos = list_entry(pos->member.next, __typeof__(*pos), member))
static void INIT_LIST_HEAD(struct list_head *h) { h->next = h->prev = h; }
static void list_add(struct list_head *n, struct list_head *h)
{
	n->next = h->next;
	n->prev = h;
	h->next->prev = n;
	h->next = n;
}
static void list_del(struct list_head *n)
{
	n->prev->next = n->next;
	n->next->prev = n->prev;
}

struct drm_private_state { int unused; };
struct drm_crtc_commit;
struct drm_dp_aux { void *drm_dev; };
struct drm_connector { const char *name; };
struct drm_dp_mst_port { struct drm_connector *connector; };
struct drm_dp_mst_branch;
struct drm_dp_mst_topology_mgr {
	void *dev;
	struct drm_dp_aux *aux;
	struct drm_dp_mst_branch *mst_primary;
	int lock;
	int max_payloads;
	u8 payload_count;
	u8 next_start_slot;
};
struct dc_link { u32 kbps; };
#define dc_link_get_link_cap(link) NULL
#define dc_link_bandwidth_kbps(link, cap) ((link)->kbps)

/* What the payload helpers wrote: DPCD payload-table rows and
 * ALLOCATE_PAYLOAD sideband requests, as text. */
static char trace[256];
static void note(const char *fmt, int a, int b, int c)
{
	char s[32];
	snprintf(s, sizeof(s), fmt, a, b, c);
	strncat(trace, s, sizeof(trace) - strlen(trace) - 1);
}
static int drm_dp_dpcd_write_byte(struct drm_dp_aux *aux, unsigned int offset, u8 value)
{
	(void)aux;
	(void)offset;
	(void)value;
	return 1;
}
static int drm_dp_dpcd_write_data(struct drm_dp_aux *aux, unsigned int offset, void *buf,
				  size_t size)
{
	u8 *b = buf;
	(void)aux;
	if (offset == DP_PAYLOAD_ALLOCATE_SET && size == 3)
		note("w%d.%d.%d", b[0], b[1], b[2]);
	return 0;
}
static int drm_dp_dpcd_read_byte(struct drm_dp_aux *aux, unsigned int offset, u8 *value)
{
	(void)aux;
	(void)offset;
	*value = DP_PAYLOAD_TABLE_UPDATED;
	return 0;
}
static int drm_dp_payload_send_msg(struct drm_dp_mst_topology_mgr *mgr,
				   struct drm_dp_mst_port *port, int id, int pbn)
{
	(void)mgr;
	(void)port;
	note("m%d.%d", id, pbn, 0);
	return 0;
}
static struct drm_dp_mst_port *drm_dp_mst_topology_get_port_validated(
	struct drm_dp_mst_topology_mgr *mgr, struct drm_dp_mst_port *port)
{
	(void)mgr;
	return port;
}
static void drm_dp_mst_topology_put_port(struct drm_dp_mst_port *port) { (void)port; }
static void drm_dp_mst_put_port_malloc(struct drm_dp_mst_port *port) { (void)port; }
static bool drm_dp_mst_port_downstream_of_branch(struct drm_dp_mst_port *port,
						 struct drm_dp_mst_branch *branch)
{
	(void)port;
	(void)branch;
	return true;
}
