/* Linux reference for amdgpu_gem.rs's dumb-buffer layout; see check.sh.
 *
 * check.sh extracts Linux's own functions verbatim: drm_dumb_buffers.c's
 * drm_mode_create_dumb, amdgpu_gem.c's amdgpu_gem_align_pitch and
 * amdgpu_mode_dumb_create, amdgpu_display.c's
 * amdgpu_display_supported_domains and amdgpu_object.c's
 * amdgpu_bo_get_preferred_domain. The stand-ins below model an RX 9070 XT:
 * a dGPU with DC, no gpu_vm_support, its buffer functions (SDMA) running,
 * USWC supported (x86).
 *
 * Input lines (stdin), one output line each:
 *   C <width> <height> <bpp>  CREATE_DUMB (decimal): the negative errno, or
 *                             "0 <pitch> <size> <domain> <flags>" (pitch
 *                             and size decimal; the domain and the flags
 *                             amdgpu_gem_object_create is called with, hex)
 */
#include <errno.h>
#define __user
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <drm/drm_mode.h>
#include <drm/amdgpu_drm.h>

typedef int8_t s8;
typedef uint32_t u32;
typedef uint64_t u64;
#define U32_MAX ((u32)~0U)
#define PAGE_SIZE 4096UL
/* include/uapi/linux/const.h, include/linux/align.h and mm.h */
#define __ALIGN_KERNEL(x, a) __ALIGN_KERNEL_MASK(x, (__typeof__(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) __ALIGN_KERNEL((x), (a))
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define check_add_overflow(a, b, d) __builtin_add_overflow(a, b, d)
#define check_mul_overflow(a, b, d) __builtin_mul_overflow(a, b, d)
#define CONFIG_DRM_AMD_DC 1
#define AMDGPU_SG_THRESHOLD (256ULL << 20)

enum amd_asic_type { CHIP_CARRIZO = 1, CHIP_STONEY, CHIP_IP_DISCOVERY };
enum ttm_bo_type { ttm_bo_type_device };
struct dma_resv;
struct drm_file { void *driver_priv; };
struct drm_device;
struct drm_driver {
	int (*dumb_create)(struct drm_file *, struct drm_device *, struct drm_mode_create_dumb *);
};
struct drm_device { const struct drm_driver *driver; };
struct drm_gem_object { int unused; };
struct amdgpu_fpriv { int xcp_id; };
struct amdgpu_device {
	struct { bool buffer_funcs_enabled; } mman;
	bool dc_enabled;
	struct { bool gpu_vm_support; } mode_info;
	enum amd_asic_type asic_type;
	struct { u64 real_vram_size; } gmc;
};
static struct amdgpu_device the_adev = {
	.mman = { .buffer_funcs_enabled = true },
	.dc_enabled = true,
	.mode_info = { .gpu_vm_support = false },
	.asic_type = CHIP_IP_DISCOVERY,
	.gmc = { .real_vram_size = 16ULL << 30 },
};
#define drm_to_adev(d) (&the_adev)
static bool amdgpu_bo_support_uswc(u64 bo_flags) { (void)bo_flags; return true; }

static struct drm_gem_object the_obj;
static u64 got_size, got_flags;
static u32 got_domain;
static int amdgpu_gem_object_create(struct amdgpu_device *adev, unsigned long size,
				    int alignment, u32 initial_domain, u64 flags,
				    enum ttm_bo_type type, struct dma_resv *resv,
				    struct drm_gem_object **obj, s8 xcp_id_plus1)
{
	(void)adev; (void)alignment; (void)type; (void)resv; (void)xcp_id_plus1;
	got_size = size;
	got_domain = initial_domain;
	got_flags = flags;
	*obj = &the_obj;
	return 0;
}
static int drm_gem_handle_create(struct drm_file *f, struct drm_gem_object *o, u32 *h)
{
	(void)f; (void)o;
	*h = 1;
	return 0;
}
static void drm_gem_object_put(struct drm_gem_object *o) { (void)o; }

#include "display.inc"
#include "object.inc"
#include "gem.inc"

static const struct drm_driver the_driver = { .dumb_create = amdgpu_mode_dumb_create };
static struct drm_device the_dev = { .driver = &the_driver };

#include "dumb.inc"

int main(void)
{
	char line[256];
	struct amdgpu_fpriv fpriv = { 0 };
	struct drm_file file = { .driver_priv = &fpriv };

	while (fgets(line, sizeof(line), stdin)) {
		unsigned long w, h, bpp;
		if (sscanf(line, "C %lu %lu %lu", &w, &h, &bpp) != 3) {
			fprintf(stderr, "bad input: %s", line);
			return 1;
		}
		struct drm_mode_create_dumb args = {
			.width = (u32)w, .height = (u32)h, .bpp = (u32)bpp,
			.handle = 7, .pitch = 7, .size = 7,
		};
		got_size = got_flags = 0;
		got_domain = 0;
		int r = drm_mode_create_dumb(&the_dev, &args, &file);
		if (r) {
			printf("%d\n", r);
			continue;
		}
		if (got_size != args.size) {
			fprintf(stderr, "size mismatch: %s", line);
			return 1;
		}
		printf("0 %u %llu %x %llx\n", args.pitch, (unsigned long long)args.size,
		       got_domain, (unsigned long long)got_flags);
	}
	return 0;
}
