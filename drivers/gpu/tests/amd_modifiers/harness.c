/* Linux reference for drivers/gpu/src/amdgpu_dm_modifiers.rs; see check.sh.
 *
 * check.sh extracts Linux's own functions verbatim (fourcc.inc, drm.inc,
 * dm.inc, display.inc): drm_format_info and its helpers, drm_plane.c's
 * create_in_format_blob and drm_plane_has_format, drm_framebuffer.c's
 * framebuffer_check, amdgpu_dm_plane.c's format lists,
 * amdgpu_dm_plane_get_plane_modifiers / add_gfx12_modifiers /
 * get_plane_formats / format_mod_supported, and amdgpu_display.c's
 * convert_tiling_flags_to_modifier_gfx12, amdgpu_display_verify_sizes and
 * amdgpu_display_gem_fb_verify_and_init. The stand-ins below model an RX
 * 9070 XT (GC 12.0.1, DCE 4.0.1, AMDGPU_FAMILY_GC_12_0_0) whose primary and
 * overlay planes carry dcn401_resource.c's plane_cap.
 *
 * Input lines (stdin), one output line each:
 *   M                       the primary's modifiers (hex), then "|" and the
 *                           overlay's
 *   P                       amdgpu_dm_plane_get_plane_formats for a DCN401
 *                           primary, as fourcc strings, then "|" and the
 *                           overlay's
 *   B <fourcc>...           the IN_FORMATS blob (hex bytes) of a plane with
 *                           these formats and the GFX12 modifiers
 *   F <fourcc> <mod>        amdgpu_dm_plane_format_mod_supported: 0 or 1
 *   T <tiling> <dcc>        convert_tiling_flags_to_modifier_gfx12 (hex)
 *   A <fourcc> <w> <h> <flags> (<handle> <pitch> <offset> <mod>)x4
 *     <tiling> <dcc> <bo_size>
 *                           ADDFB2 (all numbers hex): drm_internal_
 *                           framebuffer_create's checks, framebuffer_check,
 *                           then amdgpu_display_gem_fb_verify_and_init on a
 *                           BO of bo_size bytes with these GEM_METADATA
 *                           tiling flags and GFX12_DCC; "0 <modifier>" or
 *                           the negative errno.
 */
#include <errno.h>
#include <limits.h>
#define __user
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_mode.h>
#include <drm/amdgpu_drm.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define STATIC_IFN_KUNIT static
#define EXPORT_IF_KUNIT(x)
#define EXPORT_SYMBOL(x)
#define WARN_ON(x) (x)
#define BUILD_BUG_ON(x)
#define drm_dbg_kms(...) ((void)0)
#define pr_warn(...) ((void)0)
#define ERESTARTSYS 512
#define drm_dbg_atomic(...) ((void)0)
#define DRM_DEBUG_KMS(...) ((void)0)
#define DRM_ERROR(...) ((void)0)
#define drm_WARN_ONCE(...) ((void)0)
#define unlikely(x) (x)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define ALIGN(x, a) (((x) + (a) - 1) / (a) * (a))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define DIV_ROUND_UP_ULL(n, d) DIV_ROUND_UP((unsigned long long)(n), (unsigned long long)(d))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define GFP_KERNEL 0
#define kmalloc_array(n, s, f) malloc((n) * (s))
#define kfree free
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define BIT(n) (1u << (n))
#define DRM_FORMAT_MAX_PLANES 4u
#define DRM_FORMAT_BLOB_CURRENT 1
#define FORMAT_BLOB_CURRENT 1
#define ilog2(v) (31 - __builtin_clz(v))
#define is_power_of_2(v) ((v) && !((v) & ((v) - 1)))

static int ilog2_u(unsigned v) { return 31 - __builtin_clz(v); }

struct drm_device;
#include "fourcc.inc"

/* drm_plane / drm_device as far as these functions look. */
enum drm_plane_type { DRM_PLANE_TYPE_OVERLAY, DRM_PLANE_TYPE_PRIMARY, DRM_PLANE_TYPE_CURSOR };
struct drm_plane;
struct drm_plane_funcs {
	bool (*format_mod_supported)(struct drm_plane *, u32, u64);
};
struct drm_mode_config { bool fb_modifiers_not_supported; };
struct drm_device { struct drm_mode_config mode_config; };
struct drm_plane {
	struct drm_device *dev;
	const struct drm_plane_funcs *funcs;
	u32 *format_types;
	unsigned int format_count;
	u64 *modifiers;
	unsigned int modifier_count;
	enum drm_plane_type type;
};
struct drm_property_blob { void *data; };
static struct drm_property_blob *drm_property_create_blob(struct drm_device *dev, size_t size, const void *data)
{
	static size_t last_size;
	struct drm_property_blob *b = malloc(sizeof(*b));
	b->data = calloc(1, size);
	last_size = size;
	(void)dev; (void)data; (void)last_size;
	return b;
}
#define drm_format_info(f) __drm_format_info(f)
#include "drm.inc"

/* The amdgpu device: GC 12.0.1 / DCE 4.0.1. */
#ifndef AMDGPU_FAMILY_GC_13_0_1
#define AMDGPU_FAMILY_GC_13_0_1 0x7fff
#endif
#define IP_VERSION(a, b, c) (((a) << 16) | ((b) << 8) | (c))
enum { GC_HWIP, DCE_HWIP };
struct amdgpu_device { unsigned family; bool enable_virtual_display; struct drm_device ddev; };
static struct amdgpu_device the_adev = { .family = AMDGPU_FAMILY_GC_12_0_0 };
static unsigned amdgpu_ip_version(struct amdgpu_device *adev, int ip, int inst)
{
	(void)adev; (void)inst;
	return ip == GC_HWIP ? IP_VERSION(12, 0, 1) : IP_VERSION(4, 0, 1);
}
#define drm_to_adev(d) (&the_adev)
#define adev_to_drm(a) (&(a)->ddev)
/* Other families' lists never run on GC 12. */
#define STUB_MODS(name) static void name(struct amdgpu_device *a, uint64_t **m, uint64_t *s, uint64_t *c) { (void)a; (void)m; (void)s; (void)c; abort(); }
STUB_MODS(amdgpu_dm_plane_add_gfx6_modifiers)
STUB_MODS(amdgpu_dm_plane_add_gfx9_modifiers)
STUB_MODS(amdgpu_dm_plane_add_gfx10_1_modifiers)
STUB_MODS(amdgpu_dm_plane_add_gfx10_3_modifiers)
STUB_MODS(amdgpu_dm_plane_add_gfx11_modifiers)
static bool amdgpu_dm_plane_gfx6_format_mod_supported(struct amdgpu_device *a, u32 bpp, u64 m)
{
	(void)a; (void)bpp; (void)m;
	abort();
}
/* dcn401_resource.c plane_cap. */
enum dc_plane_type { DC_PLANE_TYPE_INVALID, DC_PLANE_TYPE_DCE_RGB, DC_PLANE_TYPE_DCE_UNDERLAY, DC_PLANE_TYPE_DCN_UNIVERSAL };
struct dc_plane_cap {
	enum dc_plane_type type;
	bool per_pixel_alpha;
	struct { bool argb8888, nv12, fp16, p010, ayuv; } pixel_format_support;
};
static const struct dc_plane_cap plane_cap = {
	.type = DC_PLANE_TYPE_DCN_UNIVERSAL,
	.per_pixel_alpha = true,
	.pixel_format_support = { .argb8888 = true, .nv12 = true, .fp16 = true, .p010 = true, .ayuv = false },
};
#include "dm.inc"

/* amdgpu_display.c's framebuffer: the BO, its tiling and GFX12_DCC. */
struct drm_gem_object { size_t size; };
struct drm_framebuffer {
	struct drm_device *dev;
	const struct drm_format_info *format;
	unsigned int pitches[DRM_FORMAT_MAX_PLANES];
	unsigned int offsets[DRM_FORMAT_MAX_PLANES];
	uint64_t modifier;
	unsigned int width, height;
	int flags;
	struct drm_gem_object *obj[DRM_FORMAT_MAX_PLANES];
};
struct amdgpu_framebuffer {
	struct drm_framebuffer base;
	uint64_t tiling_flags;
	bool tmz_surface;
	bool gfx12_dcc;
	uint64_t address;
};
struct amdgpu_bo { struct drm_gem_object tbo; u64 flags; u64 tiling_flags; };
static struct amdgpu_bo the_bo;
#define gem_to_amdgpu_bo(o) (&the_bo)
#define amdgpu_bo_reserve(b, i) 0
#define amdgpu_bo_unreserve(b)
#define amdgpu_bo_get_tiling_flags(b, t) (*(t) = (b)->tiling_flags)
#define amdgpu_bo_encrypted(b) false
#define drm_gem_object_get(o)
#define check_tiling_flags_gfx6(r) 0
#define convert_tiling_flags_to_modifier_gfx9(r) (abort(), 0)
#define convert_tiling_flags_to_modifier_gfx6(r) (abort(), 0)
static int amdgpu_display_verify_sizes_gfx6(struct drm_device *d, const u64 m, unsigned *w, unsigned *h)
{
	(void)d; (void)m; (void)w; (void)h;
	abort();
}
/* DC's GFX9 swizzle names, unreached on GFX12. */
enum { DC_SW_256B_S = 1, DC_SW_4KB_S = 5, DC_SW_64KB_S = 9, DC_SW_64KB_S_T = 13,
	DC_SW_4KB_S_X = 21, DC_SW_64KB_S_X = 25, DC_SW_VAR_S_X = 29 };
#undef ilog2
#define ilog2(v) ilog2_u(v)
struct drm_file;
static struct drm_plane planes[2];
static bool drm_any_plane_has_format(struct drm_device *dev, u32 format, u64 modifier)
{
	(void)dev;
	for (int i = 0; i < 2; i++)
		if (drm_plane_has_format(&planes[i], format, modifier))
			return true;
	return false;
}
static void drm_helper_mode_fill_fb_struct(struct drm_device *dev, struct drm_framebuffer *fb,
					   const struct drm_format_info *info,
					   const struct drm_mode_fb_cmd2 *mode_cmd)
{
	fb->dev = dev;
	fb->format = info;
	fb->width = mode_cmd->width;
	fb->height = mode_cmd->height;
	for (int i = 0; i < 4; i++) {
		fb->pitches[i] = mode_cmd->pitches[i];
		fb->offsets[i] = mode_cmd->offsets[i];
	}
	fb->modifier = mode_cmd->modifier[0];
	fb->flags = mode_cmd->flags;
}
#define drm_drv_uses_atomic_modeset(d) true
#define drm_framebuffer_init(d, f, funcs) 0
static int amdgpu_fb_funcs_atomic, amdgpu_fb_funcs;
static int amdgpu_display_framebuffer_init(struct drm_device *dev, struct amdgpu_framebuffer *rfb,
					   const struct drm_mode_fb_cmd2 *mode_cmd,
					   struct drm_gem_object *obj);
#include "display.inc"

static void fourcc_str(u32 f, char out[5])
{
	for (int i = 0; i < 4; i++)
		out[i] = (char)(f >> (8 * i));
	out[4] = 0;
}
static u32 parse_fourcc(const char *s)
{
	return (u32)s[0] | (u32)s[1] << 8 | (u32)s[2] << 16 | (u32)s[3] << 24;
}

static void plane_setup(struct drm_plane *plane, enum drm_plane_type type)
{
	static const struct drm_plane_funcs funcs = { .format_mod_supported = amdgpu_dm_plane_format_mod_supported };
	uint32_t formats[32];
	uint64_t *mods = NULL;
	int n;

	plane->type = type;
	plane->dev = &the_adev.ddev;
	plane->funcs = &funcs;
	n = amdgpu_dm_plane_get_plane_formats(plane, &plane_cap, formats, 32);
	plane->format_types = malloc(n * sizeof(u32));
	memcpy(plane->format_types, formats, n * sizeof(u32));
	plane->format_count = n;
	if (amdgpu_dm_plane_get_plane_modifiers(&the_adev, type, &mods))
		abort();
	/* drm_universal_plane_init: the list up to the INVALID terminator. */
	plane->modifier_count = 0;
	while (mods[plane->modifier_count] != DRM_FORMAT_MOD_INVALID)
		plane->modifier_count++;
	plane->modifiers = mods;
}

int main(void)
{
	char line[4096];

	plane_setup(&planes[0], DRM_PLANE_TYPE_PRIMARY);
	plane_setup(&planes[1], DRM_PLANE_TYPE_OVERLAY);
	while (fgets(line, sizeof(line), stdin)) {
		char *tok = strtok(line, " \n");
		if (!tok)
			continue;
		if (!strcmp(tok, "M") || !strcmp(tok, "P")) {
			for (int p = 0; p < 2; p++) {
				if (p)
					printf(" |");
				if (*tok == 'M') {
					for (unsigned i = 0; i < planes[p].modifier_count; i++)
						printf("%s%llx", i || p ? " " : "", (unsigned long long)planes[p].modifiers[i]);
				} else {
					for (unsigned i = 0; i < planes[p].format_count; i++) {
						char s[5];
						fourcc_str(planes[p].format_types[i], s);
						printf("%s%s", i || p ? " " : "", s);
					}
				}
			}
			printf("\n");
		} else if (!strcmp(tok, "B")) {
			struct drm_plane plane = planes[0];
			u32 formats[64];
			unsigned n = 0;
			struct drm_property_blob *blob;
			struct drm_format_modifier_blob *b;
			size_t size;

			while ((tok = strtok(NULL, " \n")))
				formats[n++] = parse_fourcc(tok);
			plane.format_types = formats;
			plane.format_count = n;
			blob = create_in_format_blob(plane.dev, &plane, plane.funcs->format_mod_supported);
			b = blob->data;
			size = b->modifiers_offset + b->count_modifiers * sizeof(struct drm_format_modifier);
			for (size_t i = 0; i < size; i++)
				printf("%02x", ((unsigned char *)b)[i]);
			printf("\n");
		} else if (!strcmp(tok, "F")) {
			u32 f = parse_fourcc(strtok(NULL, " \n"));
			u64 m = strtoull(strtok(NULL, " \n"), NULL, 16);
			printf("%d\n", amdgpu_dm_plane_format_mod_supported(&planes[0], f, m));
		} else if (!strcmp(tok, "T")) {
			struct amdgpu_framebuffer afb = { 0 };
			afb.tiling_flags = strtoull(strtok(NULL, " \n"), NULL, 16);
			afb.gfx12_dcc = strtoul(strtok(NULL, " \n"), NULL, 16);
			convert_tiling_flags_to_modifier_gfx12(&afb);
			printf("%llx\n", (unsigned long long)afb.base.modifier);
		} else if (!strcmp(tok, "A")) {
			struct drm_mode_fb_cmd2 r = { 0 };
			struct amdgpu_framebuffer rfb = { 0 };
			const struct drm_format_info *info;
			int ret;
#define NEXT strtoull(strtok(NULL, " \n"), NULL, 16)
			r.pixel_format = parse_fourcc(strtok(NULL, " \n"));
			r.width = NEXT;
			r.height = NEXT;
			r.flags = NEXT;
			for (int i = 0; i < 4; i++) {
				r.handles[i] = NEXT;
				r.pitches[i] = NEXT;
				r.offsets[i] = NEXT;
				r.modifier[i] = NEXT;
			}
			the_bo.tiling_flags = NEXT;
			the_bo.flags = NEXT ? AMDGPU_GEM_CREATE_GFX12_DCC : 0;
			the_bo.tbo.size = NEXT;
			/* drm_internal_framebuffer_create, amdgpu_dm's 16384 limits. */
			if (r.flags & ~(DRM_MODE_FB_INTERLACED | DRM_MODE_FB_MODIFIERS) ||
			    r.width > 16384 || r.height > 16384 || !__drm_format_info(r.pixel_format)) {
				printf("%d\n", -EINVAL);
				continue;
			}
			/* amdgpu_dm_plane_get_format_info: no DCC plane on GFX12. */
			info = __drm_format_info(r.pixel_format);
			ret = framebuffer_check(&the_adev.ddev, info, &r);
			if (!ret)
				ret = amdgpu_display_gem_fb_verify_and_init(&the_adev.ddev, &rfb, NULL, info, &r,
									    &the_bo.tbo);
			if (ret)
				printf("%d\n", ret);
			else
				printf("0 %llx\n", (unsigned long long)rfb.base.modifier);
		} else {
			fprintf(stderr, "bad line %s\n", tok);
			return 1;
		}
	}
	return 0;
}
