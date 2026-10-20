/* Host harness: Linux's DCN4 cursor placement, compiled from the Linux
 * tree's own functions (check.sh extracts them into linux.inc):
 * amdgpu_dm_plane_get_cursor_position, dcn401_set_cursor_position,
 * adjust_hotspot_between_slices_for_2x_magnify,
 * resource_can_pipe_disable_cursor, hubp401_cursor_set_position and
 * dpp401_set_cursor_position, on stand-ins of the structures they read.
 *
 * One stream per input line:
 *   cx cy cw ch ref_khz pix_khz n  (pipe){n}
 * the cursor's CRTC position and size, the DCHUB reference and pixel
 * clocks, then n pipes, each
 *   seg layer rx ry rw rh vx vy vw vh ratio src_w src_h slice_w
 * (ODM segment, plane layer_index, scl_data recout and viewport, SPL's
 * h_scale_ratio register value (U3.19 << 5), the plane's src_rect size and
 * the pipe's resource_get_odm_slice_src_rect width), listed segment by
 * segment, each segment's MPCC tree bottom first: consecutive pipes of a
 * segment are bottom_pipe/top_pipe, and a plane's pipes in consecutive
 * segments prev_odm_pipe/next_odm_pipe.
 * Output, per pipe in input order:
 *   CURSOR_ENABLE CURSOR_X_POSITION CURSOR_Y_POSITION CURSOR_HOT_SPOT_X
 *   CURSOR_HOT_SPOT_Y CURSOR_DST_X_OFFSET CUR0_ENABLE
 * each masked to its field. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT(x) ((void)0)
#define BREAK_TO_DEBUGGER() ((void)0)
#define DRM_ERROR(...) ((void)0)
#define EXPORT_IF_KUNIT(x)
#define EINVAL 22
#define min(a, b) ((a) < (b) ? (a) : (b))
typedef unsigned long long u64;
static inline u64 div64_u64_rem(u64 a, u64 b, u64 *rem)
{
	*rem = a % b;
	return a / b;
}
static inline long long div64_s64(long long a, long long b)
{
	return a / b;
}
#include "include/fixed31_32.h"

struct rect {
	int x, y, width, height;
};
struct dc_cursor_position {
	uint32_t x, y, x_hotspot, y_hotspot;
	bool enable;
	bool translate_by_source;
};
struct dc_stream_state;
struct dc_cursor_mi_param {
	unsigned int pixel_clk_khz, ref_clk_khz;
	struct rect viewport, recout;
	struct fixed31_32 h_scale_ratio, v_scale_ratio;
	int rotation;
	bool mirror;
	struct dc_stream_state *stream;
};
union cursor_attribute_flags {
	struct {
		uint32_t ENABLE_MAGNIFICATION : 1;
	} bits;
	uint32_t value;
};
struct dc_cursor_attributes {
	union {
		struct {
			uint32_t low_part, high_part;
		};
		long long quad_part;
	} address;
	uint32_t width, height;
	union cursor_attribute_flags attribute_flags;
};
struct hubp;
struct hubp_funcs {
	void (*set_cursor_position)(struct hubp *, const struct dc_cursor_position *,
				    const struct dc_cursor_mi_param *);
	void (*set_cursor_attributes)(struct hubp *, const struct dc_cursor_attributes *);
};
struct hubp {
	const struct hubp_funcs *funcs;
	struct dc_cursor_attributes curs_attr;
	struct dc_cursor_position curs_pos;
	struct {
		union {
			struct {
				uint32_t cur_enable;
			} bits;
		} cur_ctl;
		union {
			struct {
				uint32_t x_pos, y_pos;
			} bits;
		} position;
		union {
			struct {
				uint32_t x_hot, y_hot;
			} bits;
		} hot_spot;
		union {
			struct {
				uint32_t dst_x_offset;
			} bits;
		} dst_offset;
	} pos;
	struct rect cur_rect;
	bool cursor_offload;
};
#define dcn20_hubp hubp
#define TO_DCN20_HUBP(h) (h)
struct dpp;
struct dpp_funcs {
	void (*set_cursor_position)(struct dpp *, const struct dc_cursor_position *,
				    const struct dc_cursor_mi_param *, uint32_t, uint32_t);
};
struct dpp {
	const struct dpp_funcs *funcs;
	struct {
		union {
			struct {
				uint32_t cur0_enable;
			} bits;
		} cur0_ctl;
	} pos, att;
	bool cursor_offload;
};
#define dcn401_dpp dpp
#define TO_DCN401_DPP(d) (d)
struct dc_plane_state {
	struct rect src_rect;
	int rotation;
	bool horizontal_mirror;
	unsigned int layer_index;
	bool visible;
};
struct resource_pool {
	struct {
		unsigned int dchub_ref_clock_inKhz;
	} ref_clocks;
};
struct dc {
	struct resource_pool *res_pool;
};
struct dc_context {
	struct dc *dc;
};
struct dc_crtc_timing {
	unsigned int pix_clk_100hz;
};
struct dc_stream_state {
	struct dc_cursor_position cursor_position;
	struct dc_crtc_timing timing;
	struct dc_context *ctx;
	struct rect src, dst;
};
struct scaler_data {
	struct rect viewport, recout;
	struct {
		struct fixed31_32 horz, vert;
	} ratios;
};
struct pipe_ctx {
	struct dc_stream_state *stream;
	struct dc_plane_state *plane_state;
	struct {
		struct hubp *hubp;
		struct dpp *dpp;
		struct scaler_data scl_data;
	} plane_res;
	struct pipe_ctx *top_pipe, *bottom_pipe, *next_odm_pipe, *prev_odm_pipe;
	int odm_src_w;
};
static struct rect resource_get_odm_slice_src_rect(struct pipe_ctx *p)
{
	struct rect r = { 0, 0, p->odm_src_w, 0 };
	return r;
}
static void reverse_adjust_recout_for_visual_confirm(struct rect *r, struct pipe_ctx *p)
{
	(void)r;
	(void)p;
}
/* What each register field was set to by one pipe's programming. */
static struct {
	uint32_t CURSOR_ENABLE, CURSOR_X_POSITION, CURSOR_Y_POSITION, CURSOR_HOT_SPOT_X,
		CURSOR_HOT_SPOT_Y, CURSOR_DST_X_OFFSET, CUR0_ENABLE;
} out;
#define REG_READ(reg) 1
#define REG_UPDATE(reg, f, v) (out.f = (v))
#define REG_SET(reg, init, f, v) (out.f = (v))
#define REG_SET_2(reg, init, f1, v1, f2, v2) (out.f1 = (v1), out.f2 = (v2))

struct drm_framebuffer {
	int unused;
};
struct drm_plane_state {
	struct drm_framebuffer *fb;
	int crtc_x, crtc_y;
	unsigned int crtc_w, crtc_h;
};
struct drm_device {
	int unused;
};
struct drm_plane {
	struct drm_plane_state *state;
	struct drm_device *dev;
};
struct drm_crtc {
	int unused;
};
struct amdgpu_crtc {
	struct drm_crtc base;
	int max_cursor_width, max_cursor_height;
};
#define to_amdgpu_crtc(c) ((struct amdgpu_crtc *)(c))
struct amdgpu_device {
	int unused;
};
#define drm_to_adev(d) ((struct amdgpu_device *)(d))
#define IP_VERSION(mj, mn, rv) (((mj) << 16) | ((mn) << 8) | (rv))
/* Navi48's display IP. */
#define amdgpu_ip_version(adev, ip, inst) IP_VERSION(4, 0, 1)

#include "linux.inc"

static const struct hubp_funcs hubp_funcs = {
	.set_cursor_position = hubp401_cursor_set_position,
};
static const struct dpp_funcs dpp_funcs = {
	.set_cursor_position = dpp401_set_cursor_position,
};

#define MAX 8
int main(void)
{
	int cx, cy, cw, ch, n;
	unsigned int ref, pix;
	while (scanf("%d %d %d %d %u %u %d", &cx, &cy, &cw, &ch, &ref, &pix, &n) == 7) {
		struct pipe_ctx pipes[MAX];
		struct dc_plane_state planes[MAX];
		struct hubp hubps[MAX];
		struct dpp dpps[MAX];
		int seg[MAX], layer[MAX];
		struct resource_pool pool = { .ref_clocks = { ref } };
		struct dc dc = { &pool };
		struct dc_context ctx = { &dc };
		struct dc_stream_state stream = {
			.timing = { pix * 10 },
			.ctx = &ctx,
			.src = { 0, 0, 3840, 2160 },
			.dst = { 0, 0, 3840, 2160 },
		};
		struct drm_framebuffer fb = { 0 };
		struct drm_plane_state cursor_state = { &fb, cx, cy, (unsigned)cw, (unsigned)ch };
		struct drm_device dev = { 0 };
		struct drm_plane cursor = { &cursor_state, &dev };
		struct amdgpu_crtc crtc = { .max_cursor_width = 64, .max_cursor_height = 64 };
		memset(pipes, 0, sizeof(pipes));
		memset(planes, 0, sizeof(planes));
		memset(hubps, 0, sizeof(hubps));
		memset(dpps, 0, sizeof(dpps));
		if (n < 1 || n > MAX)
			return 1;
		for (int i = 0; i < n; i++) {
			int rx, ry, rw, rh, vx, vy, vw, vh, sw, sh, slice;
			unsigned int ratio;
			if (scanf("%d %d %d %d %d %d %d %d %d %d %u %d %d %d", &seg[i], &layer[i], &rx,
				  &ry, &rw, &rh, &vx, &vy, &vw, &vh, &ratio, &sw, &sh, &slice) != 14)
				return 1;
			struct pipe_ctx *p = &pipes[i];
			planes[i] = (struct dc_plane_state){
				.src_rect = { 0, 0, sw, sh },
				.layer_index = (unsigned)layer[i],
				.visible = true,
			};
			hubps[i].funcs = &hubp_funcs;
			hubps[i].curs_attr.address.quad_part = 0x800f00000ll;
			hubps[i].curs_attr.width = (uint32_t)cw;
			hubps[i].curs_attr.height = (uint32_t)ch;
			dpps[i].funcs = &dpp_funcs;
			p->stream = &stream;
			p->plane_state = &planes[i];
			p->plane_res.hubp = &hubps[i];
			p->plane_res.dpp = &dpps[i];
			p->plane_res.scl_data.recout = (struct rect){ rx, ry, rw, rh };
			p->plane_res.scl_data.viewport = (struct rect){ vx, vy, vw, vh };
			p->plane_res.scl_data.ratios.horz = dc_fixpt_from_ux_dy(ratio >> 5, 3, 19);
			p->plane_res.scl_data.ratios.vert = dc_fixpt_one;
			p->odm_src_w = slice;
		}
		for (int i = 0; i + 1 < n; i++) {
			if (seg[i] == seg[i + 1]) {
				pipes[i].top_pipe = &pipes[i + 1];
				pipes[i + 1].bottom_pipe = &pipes[i];
			}
		}
		for (int i = 0; i < n; i++)
			for (int j = 0; j < n; j++)
				if (seg[j] == seg[i] + 1 && layer[j] == layer[i] && !pipes[i].next_odm_pipe) {
					pipes[i].next_odm_pipe = &pipes[j];
					pipes[j].prev_odm_pipe = &pipes[i];
				}
		struct dc_cursor_position position = { 0 };
		if (amdgpu_dm_plane_get_cursor_position(&cursor, &crtc.base, &position))
			return 1;
		stream.cursor_position = position;
		for (int i = 0; i < n; i++) {
			memset(&out, 0, sizeof(out));
			dcn401_set_cursor_position(&pipes[i]);
			printf("%s%u %u %u %u %u %u %u", i ? " " : "", out.CURSOR_ENABLE,
			       out.CURSOR_X_POSITION & 0x7fff, out.CURSOR_Y_POSITION & 0x7fff,
			       out.CURSOR_HOT_SPOT_X & 0xff, out.CURSOR_HOT_SPOT_Y & 0xff,
			       out.CURSOR_DST_X_OFFSET & 0x3fff, out.CUR0_ENABLE);
		}
		printf("\n");
	}
	return 0;
}
