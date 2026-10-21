/* Linux reference for amdgpu_gem.rs's GFX12 DCC VRAM placement; see
 * check.sh.
 *
 * check.sh extracts Linux's own functions verbatim: gmc_v12_0.c's
 * gmc_v12_0_get_dcc_alignment and amdgpu_vram_mgr.c's amdgpu_vram_mgr_new
 * (with its static helpers). The stand-ins below model an RX 9000 dGPU
 * (GC 12.0.x) whose discovery table reports `tccs` texture channel caches,
 * and a buddy allocator whose free space starts at `base`: a contiguous
 * block of a power-of-two size is naturally aligned to that size, as
 * gpu_buddy hands one out, and gpu_buddy_block_trim keeps exactly the
 * trimmed range.
 *
 * Input lines (stdin), one output line each (decimal):
 *   D <gc_minor> <tccs> <size> <base>
 *     a GFX12_DCC | VRAM_CONTIGUOUS buffer of <size> bytes (page multiple)
 *     placed in a free VRAM range from byte <base> (page multiple):
 *     "<alignment> <block> <start>": gmc_v12_0_get_dcc_alignment, the
 *     block size the buddy was asked for, and where the buffer's VRAM
 *     starts (the first block once trimmed); "<alignment> -<errno>" when
 *     the allocation fails.
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int pid_t;
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define SZ_4 4
#define SZ_1K 1024
#define TASK_COMM_LEN 16
#define BIT(n) (1UL << (n))
#define PFN_UP(x) (((x) + PAGE_SIZE - 1) >> PAGE_SHIFT)
#define unlikely(x) (x)
#define BUG_ON(c) do { if (c) { puts("BUG"); exit(1); } } while (0)
#define max(a, b) ((a) > (b) ? (a) : (b))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
static inline bool is_power_of_2(unsigned long n) { return n != 0 && (n & (n - 1)) == 0; }
static inline unsigned long roundup_pow_of_two(unsigned long n)
{
	return 1UL << (64 - __builtin_clzl(n - 1));
}

struct list_head { struct list_head *next, *prev; };
#define INIT_LIST_HEAD(l) do { (l)->next = (l); (l)->prev = (l); } while (0)
static void list_add_tail(struct list_head *n, struct list_head *h)
{
	n->prev = h->prev; n->next = h; h->prev->next = n; h->prev = n;
}
#define list_entry(p, t, m) container_of(p, t, m)
#define list_first_entry_or_null(h, t, m) ((h)->next == (h) ? NULL : list_entry((h)->next, t, m))
#define list_for_each_entry(pos, head, member) \
	for (pos = list_entry((head)->next, __typeof__(*pos), member); \
	     &pos->member != (head); \
	     pos = list_entry(pos->member.next, __typeof__(*pos), member))

struct mutex { int unused; };
#define mutex_lock(m) ((void)(m))
#define mutex_unlock(m) ((void)(m))
typedef struct { long long counter; } atomic64_t;
#define atomic64_add(v, a) ((a)->counter += (v))
#define task_pid_nr(t) 0
#define get_task_comm(c, t) ((void)(c))
#define current NULL
#define kfree free
#define kzalloc_obj(x) calloc(1, sizeof(x))

#define TTM_PL_FLAG_CONTIGUOUS (1 << 0)
#define TTM_PL_FLAG_TOPDOWN (1 << 22)
enum ttm_bo_type { ttm_bo_type_device, ttm_bo_type_kernel };
enum ttm_caching { ttm_cached, ttm_write_combined };
struct ttm_place { unsigned fpfn, lpfn; u32 mem_type, flags; };
struct ttm_buffer_object {
	struct { size_t size; } base;
	enum ttm_bo_type type;
	u32 page_alignment;
};
struct ttm_resource {
	unsigned long start;
	size_t size;
	u32 placement;
	struct { enum ttm_caching caching; } bus;
};
struct ttm_resource_manager { u64 size; u64 usage; };
#define ttm_resource_manager_usage(m) ((m)->usage)
static void ttm_resource_init(struct ttm_buffer_object *bo, const struct ttm_place *place,
			      struct ttm_resource *res)
{
	(void)place;
	res->size = bo->base.size;
}
#define ttm_resource_fini(m, r) ((void)(r))

#define GPU_BUDDY_RANGE_ALLOCATION BIT(0)
#define GPU_BUDDY_TOPDOWN_ALLOCATION BIT(1)
#define GPU_BUDDY_CONTIGUOUS_ALLOCATION BIT(2)
#define GPU_BUDDY_CLEAR_ALLOCATION BIT(3)
#define GPU_BUDDY_TRIM_DISABLE BIT(5)
/* One range per block; a trimmed block keeps exactly its trimmed range. */
struct gpu_buddy_block { u64 offset, size; struct list_head link; };
struct gpu_buddy { u64 size; u64 chunk_size; u64 base; u64 asked; };
static int gpu_buddy_alloc_blocks(struct gpu_buddy *mm, u64 start, u64 end, u64 size,
				  u64 min_block_size, struct list_head *blocks,
				  unsigned long flags)
{
	(void)start; (void)flags;
	u64 align = max(roundup_pow_of_two(size), min_block_size);
	u64 at = roundup(mm->base, align);
	if (at + size > end)
		return -ENOSPC;
	struct gpu_buddy_block *b = calloc(1, sizeof(*b));
	b->offset = at;
	b->size = size;
	list_add_tail(&b->link, blocks);
	mm->asked = size;
	mm->base = at + size;
	return 0;
}
static int gpu_buddy_block_trim(struct gpu_buddy *mm, u64 *start, u64 new_size,
				struct list_head *blocks)
{
	(void)mm;
	struct gpu_buddy_block *b = list_entry(blocks->next, struct gpu_buddy_block, link);
	if (blocks->next->next != blocks || *start < b->offset ||
	    *start + new_size > b->offset + b->size)
		return -EINVAL;
	b->offset = *start;
	b->size = new_size;
	return 0;
}
#define gpu_buddy_free_list(mm, l, f) ((void)(l))
#define amdgpu_vram_mgr_block_start(b) ((b)->offset)
#define amdgpu_vram_mgr_block_size(b) ((b)->size)

#define AMDGPU_GEM_CREATE_VRAM_CLEARED (1 << 3)
#define AMDGPU_GEM_CREATE_VRAM_CONTIGUOUS (1 << 5)
#define AMDGPU_GEM_CREATE_GFX12_DCC (1 << 16)
#define AMDGPU_VM_RESERVED_VRAM (8ULL << 20)
#define GC_HWIP 1
#define IP_VERSION(mj, mn, rv) (((mj) << 16) | ((mn) << 8) | (rv))

struct amdgpu_vres_task { pid_t pid; char comm[TASK_COMM_LEN]; };
struct amdgpu_vram_mgr {
	struct ttm_resource_manager manager;
	struct gpu_buddy mm;
	struct mutex lock;
	atomic64_t vis_usage;
	u64 default_page_size;
	struct list_head allocated_vres_list;
};
struct amdgpu_vram_mgr_resource {
	struct ttm_resource base;
	struct list_head blocks;
	unsigned long flags;
	struct list_head vres_node;
	struct amdgpu_vres_task task;
};
struct amdgpu_device;
struct amdgpu_gmc_funcs { unsigned int (*get_dcc_alignment)(struct amdgpu_device *); };
struct amdgpu_device {
	struct { struct amdgpu_vram_mgr vram_mgr; } mman;
	struct {
		u64 mc_vram_size, visible_vram_size;
		const struct amdgpu_gmc_funcs *gmc_funcs;
		struct { bool connected_to_cpu; } xgmi;
	} gmc;
	struct { struct { unsigned int max_texture_channel_caches; } config; } gfx;
	u32 gc_version;
};
#define amdgpu_ip_version(adev, ip, inst) ((adev)->gc_version)
#define amdgpu_gmc_get_dcc_alignment(adev) ((adev)->gmc.gmc_funcs->get_dcc_alignment(adev))
struct amdgpu_bo { struct ttm_buffer_object tbo; u64 flags; };
#define ttm_to_amdgpu_bo(t) container_of(t, struct amdgpu_bo, tbo)

#include "gmc.inc"

static const struct amdgpu_gmc_funcs gmc_funcs = {
	.get_dcc_alignment = gmc_v12_0_get_dcc_alignment,
};

#include "vram_mgr.inc"

int main(void)
{
	char line[256];
	while (fgets(line, sizeof(line), stdin)) {
		unsigned minor, tccs;
		unsigned long long size, base;
		if (sscanf(line, "D %u %u %llu %llu", &minor, &tccs, &size, &base) != 4) {
			puts("?");
			continue;
		}
		static struct amdgpu_device adev;
		memset(&adev, 0, sizeof(adev));
		adev.gc_version = IP_VERSION(12, 0, minor);
		adev.gfx.config.max_texture_channel_caches = tccs;
		adev.gmc.gmc_funcs = &gmc_funcs;
		adev.gmc.mc_vram_size = 16ULL << 30;
		adev.gmc.visible_vram_size = 16ULL << 30;
		struct amdgpu_vram_mgr *mgr = &adev.mman.vram_mgr;
		mgr->manager.size = 16ULL << 30;
		mgr->mm.size = 16ULL << 30;
		mgr->mm.chunk_size = PAGE_SIZE;
		mgr->mm.base = base;
		mgr->default_page_size = PAGE_SIZE;
		INIT_LIST_HEAD(&mgr->allocated_vres_list);
		struct amdgpu_bo bo = {
			.tbo = { .base = { .size = size }, .type = ttm_bo_type_device },
			.flags = AMDGPU_GEM_CREATE_GFX12_DCC | AMDGPU_GEM_CREATE_VRAM_CONTIGUOUS,
		};
		struct ttm_place place = { .flags = TTM_PL_FLAG_CONTIGUOUS };
		struct ttm_resource *res;
		unsigned alignment = gmc_v12_0_get_dcc_alignment(&adev);
		int r = amdgpu_vram_mgr_new(&mgr->manager, &bo.tbo, &place, &res);
		if (r) {
			printf("%u %d\n", alignment, r);
			continue;
		}
		struct amdgpu_vram_mgr_resource *vres =
			container_of(res, struct amdgpu_vram_mgr_resource, base);
		struct gpu_buddy_block *first =
			list_entry(vres->blocks.next, struct gpu_buddy_block, link);
		printf("%u %llu %llu\n", alignment, (unsigned long long)mgr->mm.asked,
		       (unsigned long long)first->offset);
	}
	return 0;
}
