/* Host harness: amdgpu_dm's checks of an enabled DRM cursor plane on
 * DCN 4.0.1, compiled from the Linux tree's own code (check.sh extracts it
 * into linux.inc and scaled.inc): amdgpu_dm_check_native_cursor_state with
 * dm_check_cursor_fb (amdgpu_dm_cursor.c), then amdgpu_dm_atomic_check's
 * "cannot enable hardware cursor due to rotation/scaling" rule for DCN 4.x
 * (amdgpu_dm.c), on stand-ins of the structures they read. The CRTC's
 * max_cursor_width/height are dc caps' max_cursor_size, 64 on DCN 4.0.1
 * (dcn401_resource.c); the device is AMDGPU_FAMILY_GC_12_0_0 (Navi48).
 *
 * One cursor plane per input line:
 *   fb_w fb_h pitch mods tiling src_x src_y src_w src_h crtc_w crtc_h
 * the ARGB8888 framebuffer's size and byte pitch, whether it was created
 * with DRM_MODE_FB_MODIFIERS (then core DRM already took only LINEAR) or
 * else its BO's tiling flags, the plane's SRC_* (16.16) and CRTC_W/H.
 * Output: the checks' return value (0 or -EINVAL). */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define EINVAL 22
#define drm_dbg_atomic(...) ((void)0)
#define drm_dbg_driver(...) ((void)0)
typedef uint64_t __u64;

#define AMDGPU_FAMILY_AI 141
#define AMDGPU_FAMILY_GC_12_0_0 152
/* Only reached on families before GFX9, which this harness never runs. */
enum { DC_ARRAY_1D_TILED_THIN1 = 2, DC_ARRAY_2D_TILED_THIN1 = 4 };
#define DRM_MODE_FB_MODIFIERS 2
#define DRM_MODE_ROTATE_0 (1 << 0)
#define DRM_MODE_ROTATE_MASK 0xf
#include "tiling.inc"

struct drm_device;
struct amdgpu_device {
	int family;
};
static struct amdgpu_device adev_navi48 = { .family = AMDGPU_FAMILY_GC_12_0_0 };
#define drm_to_adev(dev) (&adev_navi48)
#define adev_to_drm(adev) ((struct drm_device *)0)

struct drm_crtc {
	struct drm_device *dev;
};
struct amdgpu_crtc {
	struct drm_crtc base;
	int max_cursor_width, max_cursor_height;
};
#define to_amdgpu_crtc(c) ((struct amdgpu_crtc *)(c))

struct drm_format_info {
	uint8_t cpp[4];
};
struct drm_framebuffer {
	unsigned int width, height;
	unsigned int pitches[4];
	const struct drm_format_info *format;
	int flags;
};
struct amdgpu_framebuffer {
	struct drm_framebuffer base;
	uint64_t tiling_flags;
};
#define to_amdgpu_framebuffer(f) ((struct amdgpu_framebuffer *)(f))

struct drm_plane_state {
	struct drm_crtc *crtc;
	struct drm_framebuffer *fb;
	uint32_t src_x, src_y, src_w, src_h;
	uint32_t crtc_w, crtc_h;
	unsigned int rotation;
};
struct drm_plane {
	struct drm_plane_state *state;
};
static bool drm_atomic_plane_disabling(struct drm_plane_state *old_plane_state,
				       struct drm_plane_state *new_plane_state)
{
	return old_plane_state->crtc && !new_plane_state->crtc;
}

#include "linux.inc"

/* amdgpu_dm_atomic_check's DCN 4.x cursor rule for the CRTC's new cursor
 * plane state. */
static int dcn4_cursor_rule(struct drm_plane_state *new_cursor_state)
{
	int is_rotated, is_scaled;

#include "scaled.inc"
	return (is_rotated || is_scaled) ? -EINVAL : 0;
}

int main(void)
{
	static const struct drm_format_info argb8888 = { .cpp = { 4 } };
	unsigned int w, h, pitch, mods, src_x, src_y, src_w, src_h, crtc_w, crtc_h;
	unsigned long long tiling;

	while (scanf("%u %u %u %u %llu %u %u %u %u %u %u", &w, &h, &pitch, &mods, &tiling, &src_x,
		     &src_y, &src_w, &src_h, &crtc_w, &crtc_h) == 11) {
		struct amdgpu_crtc acrtc = { .max_cursor_width = 64, .max_cursor_height = 64 };
		struct amdgpu_framebuffer afb = {
			.base = { .width = w, .height = h, .pitches = { pitch }, .format = &argb8888,
				  .flags = mods ? DRM_MODE_FB_MODIFIERS : 0 },
			.tiling_flags = tiling,
		};
		struct drm_plane_state old_state = { 0 };
		struct drm_plane_state state = {
			.crtc = &acrtc.base, .fb = &afb.base,
			.src_x = src_x, .src_y = src_y, .src_w = src_w, .src_h = src_h,
			.crtc_w = crtc_w, .crtc_h = crtc_h, .rotation = DRM_MODE_ROTATE_0,
		};
		struct drm_plane plane = { .state = &old_state };
		int ret = amdgpu_dm_check_native_cursor_state(&acrtc.base, &plane, &state, true);

		if (!ret)
			ret = dcn4_cursor_rule(&state);
		printf("%d\n", ret);
	}
	return 0;
}
