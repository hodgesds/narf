/* KMS page-flip presentation on NARF — the architecturally-correct present.
 *
 * The earlier compositors (wl_2proc/wl_multi/wl_xdg) presented by mmapping
 * /dev/fb0 and blitting client pixels straight into it. That works but it's
 * not how a real stack scans out: weston/Xorg drive DRM/KMS — allocate a
 * scanout framebuffer (dumb buffer), and on each frame PAGE_FLIP the CRTC to
 * it, waiting for the flip-complete event. This compositor does exactly that.
 *
 * It opens /dev/dri/card0, sets up a full-screen dumb-buffer scanout
 * (CREATE_DUMB → ADDFB2 → SETCRTC), then runs an xdg-shell compositor and
 * forks a client. On the client's commit it copies the client's wl_shm
 * pixels into the *dumb buffer* (never into /dev/fb0) and PAGE_FLIPs the CRTC
 * with DRM_MODE_PAGE_FLIP_EVENT, then read()s the DRM fd to drain the
 * drm_event_vblank flip-complete event.
 *
 * Verification: the compositor opens /dev/fb0 READ-ONLY and reads back fb[0].
 * Since the compositor never writes /dev/fb0, the client pixel can only be
 * there because the KMS page-flip presented the dumb buffer to the scanout.
 *
 * Prints `kms-ok WxH px=<colour> flip=1` once the client's pixel has been
 * presented via page-flip and the flip event was received.
 */
#define _GNU_SOURCE 1
#include <wayland-server-core.h>
#include <wayland-client-core.h>
#include "wayland-client-protocol.h"
#include "wayland-server-protocol.h"
#include "xdg-shell-client-protocol.h"
#include "xdg-shell-server-protocol.h"
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define FBIOGET_VSCREENINFO 0x4600
#define CLIENT_PIXEL 0x00C0FFEEu
#define SOCKNAME "wayland-kms"

/* ── DRM ioctl numbers (x86_64) ─────────────────────────────────────── */
#define DRM_IOCTL_GET_CAP           0xC010640CU
#define DRM_IOCTL_MODE_GETRESOURCES 0xC04064A0U
#define DRM_IOCTL_MODE_CREATE_DUMB  0xC02064B2U
#define DRM_IOCTL_MODE_MAP_DUMB     0xC01064B3U
#define DRM_IOCTL_MODE_ADDFB2       0xC06864B8U
#define DRM_IOCTL_MODE_SETCRTC      0xC06864A2U
#define DRM_IOCTL_MODE_PAGE_FLIP    0xC01864B0U
#define DRM_CAP_DUMB_BUFFER 0x1ULL
#define DRM_MODE_PAGE_FLIP_EVENT 0x1U
#define DRM_EVENT_FLIP_COMPLETE 0x2U

struct drm_get_cap { uint64_t capability, value; };
struct drm_mode_card_res {
    uint64_t fb_id_ptr, crtc_id_ptr, connector_id_ptr, encoder_id_ptr;
    uint32_t count_fbs, count_crtcs, count_connectors, count_encoders;
    uint32_t min_width, max_width, min_height, max_height;
};
struct drm_mode_create_dumb {
    uint32_t height, width, bpp, flags, handle, pitch; uint64_t size;
};
struct drm_mode_map_dumb { uint32_t handle, pad; uint64_t offset; };
struct drm_mode_modeinfo {
    uint32_t clock;
    uint16_t hdisplay, hsync_start, hsync_end, htotal, hskew;
    uint16_t vdisplay, vsync_start, vsync_end, vtotal, vscan;
    uint32_t vrefresh, flags, type; char name[32];
};
struct drm_mode_crtc {
    uint64_t set_connectors_ptr; uint32_t count_connectors, crtc_id, fb_id;
    uint32_t x, y, gamma_size, mode_valid; struct drm_mode_modeinfo mode;
};
struct drm_mode_fb_cmd2 {
    uint32_t fb_id, width, height, pixel_format, flags;
    uint32_t handles[4], pitches[4], offsets[4]; uint64_t modifier[4];
};
struct drm_mode_crtc_page_flip {
    uint32_t crtc_id, fb_id, flags, reserved; uint64_t user_data;
};
/* drm_event_vblank: 32 bytes */
struct drm_event_vblank {
    uint32_t type, length; uint64_t user_data;
    uint32_t tv_sec, tv_usec, sequence, crtc_id;
};

static void w(const char *s) { write(1, s, strlen(s)); }

/* ── KMS scanout state (the present target) ── */
static int drm_fd = -1, fbro_fd = -1;
static uint32_t *fbro = NULL;          /* /dev/fb0 mapped READ-ONLY for verify */
static uint32_t *dumb = NULL;          /* the DRM dumb scanout buffer */
static uint32_t kms_w = 0, kms_h = 0, kms_pitch = 0, kms_crtc = 0, kms_fb = 0;
static int flips = 0;

/* Bring up a full-screen dumb-buffer scanout on card0. Returns 0 on success. */
static int kms_setup(uint32_t W, uint32_t H) {
    drm_fd = open("/dev/dri/card0", O_RDWR);
    if (drm_fd < 0) return 1;
    struct drm_get_cap cap; memset(&cap, 0, sizeof cap);
    cap.capability = DRM_CAP_DUMB_BUFFER;
    if (ioctl(drm_fd, DRM_IOCTL_GET_CAP, &cap) != 0 || cap.value != 1) return 2;

    struct drm_mode_card_res res; memset(&res, 0, sizeof res);
    if (ioctl(drm_fd, DRM_IOCTL_MODE_GETRESOURCES, &res) != 0) return 3;
    if (res.count_crtcs == 0 || res.count_connectors == 0) return 4;
    uint32_t crtcs[8], conns[8];
    memset(crtcs, 0, sizeof crtcs); memset(conns, 0, sizeof conns);
    res.crtc_id_ptr = (uint64_t)(uintptr_t)crtcs;
    res.connector_id_ptr = (uint64_t)(uintptr_t)conns;
    res.count_crtcs = res.count_crtcs < 8 ? res.count_crtcs : 8;
    res.count_connectors = res.count_connectors < 8 ? res.count_connectors : 8;
    if (ioctl(drm_fd, DRM_IOCTL_MODE_GETRESOURCES, &res) != 0) return 5;
    kms_crtc = crtcs[0];
    uint32_t conn = conns[0];
    if (kms_crtc == 0) return 6;

    struct drm_mode_create_dumb cd; memset(&cd, 0, sizeof cd);
    cd.width = W; cd.height = H; cd.bpp = 32;
    if (ioctl(drm_fd, DRM_IOCTL_MODE_CREATE_DUMB, &cd) != 0 || cd.handle == 0) return 7;
    kms_pitch = cd.pitch;
    struct drm_mode_map_dumb md; memset(&md, 0, sizeof md);
    md.handle = cd.handle;
    if (ioctl(drm_fd, DRM_IOCTL_MODE_MAP_DUMB, &md) != 0 || md.offset == 0) return 8;
    dumb = mmap(NULL, (size_t)cd.size, PROT_READ | PROT_WRITE, MAP_SHARED, drm_fd, (off_t)md.offset);
    if (dumb == MAP_FAILED) return 9;
    memset(dumb, 0, (size_t)cd.size);

    struct drm_mode_fb_cmd2 fb; memset(&fb, 0, sizeof fb);
    fb.width = W; fb.height = H; fb.pixel_format = 0x34325258U; /* XR24 */
    fb.handles[0] = cd.handle; fb.pitches[0] = kms_pitch;
    if (ioctl(drm_fd, DRM_IOCTL_MODE_ADDFB2, &fb) != 0 || fb.fb_id == 0) return 10;
    kms_fb = fb.fb_id;

    struct drm_mode_crtc sc; memset(&sc, 0, sizeof sc);
    sc.crtc_id = kms_crtc; sc.fb_id = kms_fb;
    sc.set_connectors_ptr = (uint64_t)(uintptr_t)&conn;
    sc.count_connectors = 1; sc.mode_valid = 1;
    sc.mode.hdisplay = (uint16_t)W; sc.mode.vdisplay = (uint16_t)H;
    sc.mode.htotal = (uint16_t)(W + 160); sc.mode.vtotal = (uint16_t)(H + 45);
    sc.mode.vrefresh = 60;
    snprintf(sc.mode.name, sizeof sc.mode.name, "%ux%u", W, H);
    if (ioctl(drm_fd, DRM_IOCTL_MODE_SETCRTC, &sc) != 0) return 11;

    kms_w = W; kms_h = H;
    return 0;
}

/* Present the current dumb buffer to the CRTC via page-flip, then drain the
 * flip-complete event from the DRM fd. This is the present primitive. */
static void kms_present(void) {
    struct drm_mode_crtc_page_flip pf; memset(&pf, 0, sizeof pf);
    pf.crtc_id = kms_crtc; pf.fb_id = kms_fb;
    pf.flags = DRM_MODE_PAGE_FLIP_EVENT; pf.user_data = 0xF11Du;
    if (ioctl(drm_fd, DRM_IOCTL_MODE_PAGE_FLIP, &pf) != 0) return;
    struct drm_event_vblank ev; memset(&ev, 0, sizeof ev);
    ssize_t n = read(drm_fd, &ev, sizeof ev);
    if (n == (ssize_t)sizeof ev && ev.type == DRM_EVENT_FLIP_COMPLETE) flips++;
}

/* ───────────────────────── server (compositor) ───────────────────────── */

struct surf { struct wl_resource *pending, *xdg, *toplevel; int config_sent, configured; };
static int presented_ok = 0;
static uint32_t serial_ctr = 0;

static void su_destroy(struct wl_client *c, struct wl_resource *r) { (void)c; wl_resource_destroy(r); }
static void su_attach(struct wl_client *c, struct wl_resource *r, struct wl_resource *b, int32_t x, int32_t y)
{ (void)c; (void)x; (void)y; ((struct surf *)wl_resource_get_user_data(r))->pending = b; }
static void su_nop4(struct wl_client *c, struct wl_resource *r, int32_t a, int32_t b, int32_t cc, int32_t d)
{ (void)c; (void)r; (void)a; (void)b; (void)cc; (void)d; }
static void su_frame(struct wl_client *c, struct wl_resource *r, uint32_t cb) { (void)c; (void)r; (void)cb; }
static void su_reg(struct wl_client *c, struct wl_resource *r, struct wl_resource *reg) { (void)c; (void)r; (void)reg; }
static void su_commit(struct wl_client *c, struct wl_resource *r) {
    (void)c;
    struct surf *s = wl_resource_get_user_data(r);
    if (s->xdg && !s->configured) {
        if (!s->config_sent) {
            struct wl_array states; wl_array_init(&states);
            xdg_toplevel_send_configure(s->toplevel, 0, 0, &states);
            wl_array_release(&states);
            xdg_surface_send_configure(s->xdg, ++serial_ctr);
            s->config_sent = 1;
        }
        return;
    }
    if (!s->pending) return;
    struct wl_shm_buffer *shm = wl_shm_buffer_get(s->pending);
    if (!shm) return;
    wl_shm_buffer_begin_access(shm);
    uint32_t *src = wl_shm_buffer_get_data(shm);
    int bw = wl_shm_buffer_get_width(shm), bh = wl_shm_buffer_get_height(shm);
    int bstride = wl_shm_buffer_get_stride(shm) / 4;
    int dpitch = (int)(kms_pitch / 4);
    /* Compose into the DRM dumb buffer — NOT /dev/fb0. */
    for (int y = 0; y < bh && y < (int)kms_h; y++)
        for (int x = 0; x < bw && x < (int)kms_w; x++)
            dumb[y * dpitch + x] = src[y * bstride + x];
    wl_shm_buffer_end_access(shm);
    kms_present(); /* scan it out via KMS page-flip */
    presented_ok = 1;
    wl_buffer_send_release(s->pending);
    s->pending = NULL;
}
static void su_i1(struct wl_client *c, struct wl_resource *r, int32_t a) { (void)c; (void)r; (void)a; }
static void su_offset(struct wl_client *c, struct wl_resource *r, int32_t x, int32_t y) { (void)c; (void)r; (void)x; (void)y; }
static const struct wl_surface_interface surface_impl = {
    su_destroy, su_attach, su_nop4, su_frame, su_reg, su_reg,
    su_commit, su_i1, su_i1, su_nop4, su_offset,
};
static void surf_free(struct wl_resource *r) { free(wl_resource_get_user_data(r)); }
static void co_create_surface(struct wl_client *c, struct wl_resource *r, uint32_t id) {
    struct surf *s = calloc(1, sizeof *s);
    struct wl_resource *sr = wl_resource_create(c, &wl_surface_interface, wl_resource_get_version(r), id);
    wl_resource_set_implementation(sr, &surface_impl, s, surf_free);
}
static void co_create_region(struct wl_client *c, struct wl_resource *r, uint32_t id) { (void)c; (void)r; (void)id; }
static const struct wl_compositor_interface compositor_impl = { co_create_surface, co_create_region };
static void compositor_bind(struct wl_client *c, void *data, uint32_t ver, uint32_t id) {
    (void)data;
    struct wl_resource *r = wl_resource_create(c, &wl_compositor_interface, ver, id);
    wl_resource_set_implementation(r, &compositor_impl, NULL, NULL);
}

/* xdg-shell server impl (same as Rung 8) */
static void xt_destroy(struct wl_client *c, struct wl_resource *r) { (void)c; wl_resource_destroy(r); }
static void xt_set_parent(struct wl_client *c, struct wl_resource *r, struct wl_resource *p) { (void)c; (void)r; (void)p; }
static void xt_set_str(struct wl_client *c, struct wl_resource *r, const char *t) { (void)c; (void)r; (void)t; }
static void xt_show_menu(struct wl_client *c, struct wl_resource *r, struct wl_resource *s, uint32_t e, int32_t x, int32_t y)
{ (void)c; (void)r; (void)s; (void)e; (void)x; (void)y; }
static void xt_move(struct wl_client *c, struct wl_resource *r, struct wl_resource *s, uint32_t e) { (void)c; (void)r; (void)s; (void)e; }
static void xt_resize(struct wl_client *c, struct wl_resource *r, struct wl_resource *s, uint32_t e, uint32_t ed)
{ (void)c; (void)r; (void)s; (void)e; (void)ed; }
static void xt_set_wh(struct wl_client *c, struct wl_resource *r, int32_t wd, int32_t h) { (void)c; (void)r; (void)wd; (void)h; }
static void xt_nop(struct wl_client *c, struct wl_resource *r) { (void)c; (void)r; }
static void xt_set_fs(struct wl_client *c, struct wl_resource *r, struct wl_resource *o) { (void)c; (void)r; (void)o; }
static const struct xdg_toplevel_interface toplevel_impl = {
    xt_destroy, xt_set_parent, xt_set_str, xt_set_str, xt_show_menu,
    xt_move, xt_resize, xt_set_wh, xt_set_wh, xt_nop, xt_nop, xt_set_fs, xt_nop, xt_nop,
};
static void xs_destroy(struct wl_client *c, struct wl_resource *r) { (void)c; wl_resource_destroy(r); }
static void xs_get_toplevel(struct wl_client *c, struct wl_resource *r, uint32_t id) {
    struct surf *s = wl_resource_get_user_data(r);
    struct wl_resource *tr = wl_resource_create(c, &xdg_toplevel_interface, wl_resource_get_version(r), id);
    wl_resource_set_implementation(tr, &toplevel_impl, s, NULL);
    s->toplevel = tr;
}
static void xs_get_popup(struct wl_client *c, struct wl_resource *r, uint32_t id, struct wl_resource *p, struct wl_resource *pos)
{ (void)c; (void)r; (void)id; (void)p; (void)pos; }
static void xs_set_geom(struct wl_client *c, struct wl_resource *r, int32_t x, int32_t y, int32_t wd, int32_t h)
{ (void)c; (void)r; (void)x; (void)y; (void)wd; (void)h; }
static void xs_ack_configure(struct wl_client *c, struct wl_resource *r, uint32_t serial) {
    (void)c; (void)serial;
    ((struct surf *)wl_resource_get_user_data(r))->configured = 1;
}
static const struct xdg_surface_interface xdg_surface_impl = {
    xs_destroy, xs_get_toplevel, xs_get_popup, xs_set_geom, xs_ack_configure,
};
static void wm_destroy(struct wl_client *c, struct wl_resource *r) { (void)c; wl_resource_destroy(r); }
static void wm_create_positioner(struct wl_client *c, struct wl_resource *r, uint32_t id)
{ (void)r; wl_resource_destroy(wl_resource_create(c, &xdg_positioner_interface, 1, id)); }
static void wm_get_xdg_surface(struct wl_client *c, struct wl_resource *r, uint32_t id, struct wl_resource *surface) {
    struct surf *s = wl_resource_get_user_data(surface);
    struct wl_resource *xr = wl_resource_create(c, &xdg_surface_interface, wl_resource_get_version(r), id);
    wl_resource_set_implementation(xr, &xdg_surface_impl, s, NULL);
    s->xdg = xr;
}
static void wm_pong(struct wl_client *c, struct wl_resource *r, uint32_t serial) { (void)c; (void)r; (void)serial; }
static const struct xdg_wm_base_interface wm_impl = {
    wm_destroy, wm_create_positioner, wm_get_xdg_surface, wm_pong,
};
static void wm_bind(struct wl_client *c, void *data, uint32_t ver, uint32_t id) {
    (void)data;
    struct wl_resource *r = wl_resource_create(c, &xdg_wm_base_interface, ver, id);
    wl_resource_set_implementation(r, &wm_impl, NULL, NULL);
}

/* ───────────────────────────── client ───────────────────────────────── */

static uint32_t comp_name = 0, comp_ver = 0, shm_name = 0, shm_ver = 0, wm_name = 0, wm_ver = 0;
static void reg_global(void *d, struct wl_registry *r, uint32_t name, const char *iface, uint32_t ver) {
    (void)d; (void)r;
    if (!strcmp(iface, "wl_compositor")) { comp_name = name; comp_ver = ver; }
    else if (!strcmp(iface, "wl_shm")) { shm_name = name; shm_ver = ver; }
    else if (!strcmp(iface, "xdg_wm_base")) { wm_name = name; wm_ver = ver; }
}
static void reg_remove(void *d, struct wl_registry *r, uint32_t n) { (void)d; (void)r; (void)n; }
static const struct wl_registry_listener reg_l = { reg_global, reg_remove };
static int cl_acked = 0;
static void cl_ping(void *d, struct xdg_wm_base *wm, uint32_t serial) { (void)d; xdg_wm_base_pong(wm, serial); }
static const struct xdg_wm_base_listener wm_listener = { cl_ping };
static void cl_xsurf_configure(void *d, struct xdg_surface *xs, uint32_t serial) {
    (void)d; xdg_surface_ack_configure(xs, serial); cl_acked = 1;
}
static const struct xdg_surface_listener xsurf_listener = { cl_xsurf_configure };
static void cl_top_configure(void *d, struct xdg_toplevel *t, int32_t w_, int32_t h_, struct wl_array *st)
{ (void)d; (void)t; (void)w_; (void)h_; (void)st; }
static void cl_top_close(void *d, struct xdg_toplevel *t) { (void)d; (void)t; }
static void cl_top_bounds(void *d, struct xdg_toplevel *t, int32_t w_, int32_t h_) { (void)d; (void)t; (void)w_; (void)h_; }
static void cl_top_caps(void *d, struct xdg_toplevel *t, struct wl_array *c) { (void)d; (void)t; (void)c; }
static const struct xdg_toplevel_listener top_listener = {
    cl_top_configure, cl_top_close, cl_top_bounds, cl_top_caps,
};

static int run_client(void) {
    struct wl_display *d = NULL;
    for (int i = 0; i < 200 && !d; i++) { d = wl_display_connect(SOCKNAME); if (!d) usleep(20000); }
    if (!d) return 11;
    struct wl_registry *reg = wl_display_get_registry(d);
    wl_registry_add_listener(reg, &reg_l, NULL);
    wl_display_roundtrip(d);
    if (!comp_name || !shm_name || !wm_name) return 12;
    struct wl_compositor *comp = wl_registry_bind(reg, comp_name, &wl_compositor_interface, comp_ver);
    struct wl_shm *shm = wl_registry_bind(reg, shm_name, &wl_shm_interface, shm_ver);
    struct xdg_wm_base *wm = wl_registry_bind(reg, wm_name, &xdg_wm_base_interface, wm_ver);
    xdg_wm_base_add_listener(wm, &wm_listener, NULL);
    struct wl_surface *surf = wl_compositor_create_surface(comp);
    struct xdg_surface *xsurf = xdg_wm_base_get_xdg_surface(wm, surf);
    xdg_surface_add_listener(xsurf, &xsurf_listener, NULL);
    struct xdg_toplevel *top = xdg_surface_get_toplevel(xsurf);
    xdg_toplevel_add_listener(top, &top_listener, NULL);
    xdg_toplevel_set_title(top, "narf-kms");
    wl_surface_commit(surf);
    for (int i = 0; i < 200 && !cl_acked; i++) wl_display_roundtrip(d);
    if (!cl_acked) return 15;
    const int W = 64, H = 64;
    int mfd = memfd_create("c", 0);
    if (mfd < 0 || ftruncate(mfd, W * H * 4) != 0) return 13;
    uint32_t *px = mmap(0, W * H * 4, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    if (px == MAP_FAILED) return 14;
    for (int i = 0; i < W * H; i++) px[i] = CLIENT_PIXEL;
    struct wl_shm_pool *pool = wl_shm_create_pool(shm, mfd, W * H * 4);
    struct wl_buffer *buf = wl_shm_pool_create_buffer(pool, 0, W, H, W * 4, WL_SHM_FORMAT_XRGB8888);
    wl_surface_attach(surf, buf, 0, 0);
    wl_surface_commit(surf);
    wl_display_roundtrip(d);
    wl_display_roundtrip(d);
    return 0;
}

int main(void) {
    setenv("XDG_RUNTIME_DIR", "/tmp", 1);

    /* Read the scanout geometry from /dev/fb0 (also our read-only verify map). */
    fbro_fd = open("/dev/fb0", O_RDONLY);
    if (fbro_fd < 0) { w("kms-fail-fb\n"); return 1; }
    uint32_t v[40]; memset(v, 0, sizeof v);
    if (ioctl(fbro_fd, FBIOGET_VSCREENINFO, v) != 0 || v[0] == 0 || v[1] == 0) { w("kms-fail-vinfo\n"); return 1; }
    uint32_t W = v[0], H = v[1];
    size_t fblen = ((size_t)W * H * 4 + 0xFFF) & ~(size_t)0xFFF;
    fbro = mmap(0, fblen, PROT_READ, MAP_SHARED, fbro_fd, 0);
    if (fbro == MAP_FAILED) { w("kms-fail-fbmap\n"); return 1; }

    int rc = kms_setup(W, H);
    if (rc != 0) { char b[48]; int n = snprintf(b, sizeof b, "kms-fail-setup-%d\n", rc); write(1, b, n); return 1; }

    struct wl_display *server = wl_display_create();
    if (!server) { w("kms-fail-create\n"); return 1; }
    if (wl_display_init_shm(server) != 0) { w("kms-fail-shm\n"); return 1; }
    wl_global_create(server, &wl_compositor_interface, 4, NULL, compositor_bind);
    wl_global_create(server, &xdg_wm_base_interface, 1, NULL, wm_bind);
    if (wl_display_add_socket(server, SOCKNAME) != 0) { w("kms-fail-socket\n"); return 1; }

    pid_t pid = fork();
    if (pid < 0) { w("kms-fail-fork\n"); return 1; }
    if (pid == 0) { _exit(run_client()); }

    struct wl_event_loop *loop = wl_display_get_event_loop(server);
    int st = 0;
    for (int i = 0; i < 800; i++) {
        wl_event_loop_dispatch(loop, 50);
        wl_display_flush_clients(server);
        if (waitpid(pid, &st, WNOHANG) == pid) break;
    }

    if (!presented_ok) { w("kms-fail-nopresent\n"); return 1; }
    if (flips < 1) { w("kms-fail-noflip\n"); return 1; }
    /* The compositor never wrote /dev/fb0; if the client pixel is on the
     * scanout, the KMS page-flip presented it. */
    if (fbro[0] != CLIENT_PIXEL) {
        char db[128];
        int dn = snprintf(db, sizeof db,
            "kms-fail-pixel fb0=%08x dumb0=%08x pitch=%u present=%d flip=%d\n",
            fbro[0], dumb ? dumb[0] : 0xDEADu, kms_pitch, presented_ok, flips);
        write(1, db, dn);
        return 1;
    }
    char b[96];
    int n = snprintf(b, sizeof b, "kms-ok %ux%u px=%08x flip=%d\n", W, H, fbro[0], flips);
    write(1, b, n);
    return 0;
}
