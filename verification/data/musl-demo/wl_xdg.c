/* xdg-shell on NARF — the window-management protocol real toolkits use.
 *
 * Core Wayland (wl_compositor/wl_surface/wl_shm) only moves pixels; it has
 * no concept of a "window". Every real GUI toolkit (GTK, Qt, SDL, EFL)
 * maps its top-level window through the xdg-shell protocol — xdg_wm_base →
 * xdg_surface → xdg_toplevel — and aborts at startup if the compositor
 * doesn't advertise it. This proves NARF runs that handshake end to end.
 *
 * fork(): the parent is a compositor that advertises wl_compositor, wl_shm
 * AND xdg_wm_base, and blits a mapped toplevel's buffer to /dev/fb0; the
 * child is an independent client that creates an xdg_toplevel and drives
 * the standard map sequence:
 *
 *   create xdg_surface + xdg_toplevel  →  initial wl_surface.commit (no
 *   buffer)  →  server sends xdg_toplevel.configure + xdg_surface.configure
 *   →  client ack_configure  →  attach a wl_shm buffer + commit  →  the
 *   compositor composites the now-mapped window.
 *
 * The parent prints `xdg-ok WxH px=<colour>` once the toplevel's pixel
 * lands on the framebuffer.
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
#define SOCKNAME "wayland-xdg"

static uint32_t *fb = NULL;
static int fb_w = 0, fb_h = 0;
static void w(const char *s) { write(1, s, strlen(s)); }

static int open_fb(void) {
    int fd = open("/dev/fb0", O_RDWR);
    if (fd < 0) return -1;
    uint32_t v[40];
    memset(v, 0, sizeof v);
    if (ioctl(fd, FBIOGET_VSCREENINFO, v) != 0) return -1;
    fb_w = v[0]; fb_h = v[1];
    if (fb_w == 0 || fb_h == 0) return -1;
    size_t len = ((size_t)fb_w * fb_h * 4 + 0xFFF) & ~(size_t)0xFFF;
    fb = mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    return fb == MAP_FAILED ? -1 : 0;
}

/* ───────────────────────── server (compositor) ───────────────────────── */

/* Per-wl_surface state. xdg holds the xdg_surface role object once assigned;
 * `configured` flips when the client acks our initial configure (the window
 * is then mapped and a committed buffer may be shown). */
struct surf {
    struct wl_resource *pending;   /* attached wl_buffer awaiting commit */
    struct wl_resource *xdg;       /* xdg_surface role object, or NULL */
    struct wl_resource *toplevel;  /* xdg_toplevel, or NULL */
    int config_sent;               /* sent the initial configure? */
    int configured;                /* client acked it? (window mapped) */
};
static int mapped_ok = 0;
static uint32_t serial_ctr = 0;

/* wl_surface impl */
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
    /* Initial commit of an xdg_surface with no buffer yet: respond with the
     * mandatory configure sequence (toplevel size, then xdg_surface serial). */
    if (s->xdg && !s->configured) {
        if (!s->config_sent) {
            struct wl_array states;
            wl_array_init(&states);
            xdg_toplevel_send_configure(s->toplevel, 0, 0, &states);
            wl_array_release(&states);
            xdg_surface_send_configure(s->xdg, ++serial_ctr);
            s->config_sent = 1;
        }
        return;
    }
    /* Mapped window with an attached buffer → composite it. */
    if (!s->pending) return;
    struct wl_shm_buffer *shm = wl_shm_buffer_get(s->pending);
    if (!shm) return;
    wl_shm_buffer_begin_access(shm);
    uint32_t *src = wl_shm_buffer_get_data(shm);
    int bw = wl_shm_buffer_get_width(shm), bh = wl_shm_buffer_get_height(shm);
    int bstride = wl_shm_buffer_get_stride(shm) / 4;
    for (int y = 0; y < bh && y < fb_h; y++)
        for (int x = 0; x < bw && x < fb_w; x++)
            fb[y * fb_w + x] = src[y * bstride + x];
    wl_shm_buffer_end_access(shm);
    mapped_ok = 1;
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

/* xdg_toplevel impl — all requests are no-ops for this test. */
static void xt_destroy(struct wl_client *c, struct wl_resource *r) { (void)c; wl_resource_destroy(r); }
static void xt_set_parent(struct wl_client *c, struct wl_resource *r, struct wl_resource *p) { (void)c; (void)r; (void)p; }
static void xt_set_title(struct wl_client *c, struct wl_resource *r, const char *t) { (void)c; (void)r; (void)t; }
static void xt_set_app_id(struct wl_client *c, struct wl_resource *r, const char *a) { (void)c; (void)r; (void)a; }
static void xt_show_menu(struct wl_client *c, struct wl_resource *r, struct wl_resource *s, uint32_t e, int32_t x, int32_t y)
{ (void)c; (void)r; (void)s; (void)e; (void)x; (void)y; }
static void xt_move(struct wl_client *c, struct wl_resource *r, struct wl_resource *s, uint32_t e) { (void)c; (void)r; (void)s; (void)e; }
static void xt_resize(struct wl_client *c, struct wl_resource *r, struct wl_resource *s, uint32_t e, uint32_t ed)
{ (void)c; (void)r; (void)s; (void)e; (void)ed; }
static void xt_set_wh(struct wl_client *c, struct wl_resource *r, int32_t wd, int32_t h) { (void)c; (void)r; (void)wd; (void)h; }
static void xt_nop(struct wl_client *c, struct wl_resource *r) { (void)c; (void)r; }
static void xt_set_fs(struct wl_client *c, struct wl_resource *r, struct wl_resource *o) { (void)c; (void)r; (void)o; }
static const struct xdg_toplevel_interface toplevel_impl = {
    xt_destroy, xt_set_parent, xt_set_title, xt_set_app_id, xt_show_menu,
    xt_move, xt_resize, xt_set_wh, xt_set_wh, xt_nop, xt_nop, xt_set_fs, xt_nop, xt_nop,
};

/* xdg_surface impl */
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
    ((struct surf *)wl_resource_get_user_data(r))->configured = 1; /* window mapped */
}
static const struct xdg_surface_interface xdg_surface_impl = {
    xs_destroy, xs_get_toplevel, xs_get_popup, xs_set_geom, xs_ack_configure,
};

/* xdg_wm_base impl */
static void wm_destroy(struct wl_client *c, struct wl_resource *r) { (void)c; wl_resource_destroy(r); }
static void wm_create_positioner(struct wl_client *c, struct wl_resource *r, uint32_t id)
{ (void)r; wl_resource_destroy(wl_resource_create(c, &xdg_positioner_interface, 1, id)); }
static void wm_get_xdg_surface(struct wl_client *c, struct wl_resource *r, uint32_t id, struct wl_resource *surface) {
    (void)r;
    struct surf *s = wl_resource_get_user_data(surface); /* the wl_surface's state */
    struct wl_resource *xr = wl_resource_create(c, &xdg_surface_interface, wl_resource_get_version(r), id);
    wl_resource_set_implementation(xr, &xdg_surface_impl, s, NULL);
    s->xdg = xr; /* assign the xdg_surface role */
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
    (void)d;
    xdg_surface_ack_configure(xs, serial); /* accept the configured state */
    cl_acked = 1;
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
    if (!comp_name || !shm_name || !wm_name) return 12; /* no xdg_wm_base → no windows */

    struct wl_compositor *comp = wl_registry_bind(reg, comp_name, &wl_compositor_interface, comp_ver);
    struct wl_shm *shm = wl_registry_bind(reg, shm_name, &wl_shm_interface, shm_ver);
    struct xdg_wm_base *wm = wl_registry_bind(reg, wm_name, &xdg_wm_base_interface, wm_ver);
    xdg_wm_base_add_listener(wm, &wm_listener, NULL);

    /* The xdg-shell map sequence. */
    struct wl_surface *surf = wl_compositor_create_surface(comp);
    struct xdg_surface *xsurf = xdg_wm_base_get_xdg_surface(wm, surf);
    xdg_surface_add_listener(xsurf, &xsurf_listener, NULL);
    struct xdg_toplevel *top = xdg_surface_get_toplevel(xsurf);
    xdg_toplevel_add_listener(top, &top_listener, NULL);
    xdg_toplevel_set_title(top, "narf-xdg");
    wl_surface_commit(surf); /* initial commit, no buffer → triggers configure */

    /* Wait for the server's configure, then ack happens in the listener. */
    for (int i = 0; i < 200 && !cl_acked; i++) wl_display_roundtrip(d);
    if (!cl_acked) return 15;

    /* Window is mapped: paint a buffer, attach, commit. */
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
    if (open_fb() != 0) { w("xdg-fail-fb\n"); return 1; }

    struct wl_display *server = wl_display_create();
    if (!server) { w("xdg-fail-create\n"); return 1; }
    if (wl_display_init_shm(server) != 0) { w("xdg-fail-shm\n"); return 1; }
    wl_global_create(server, &wl_compositor_interface, 4, NULL, compositor_bind);
    wl_global_create(server, &xdg_wm_base_interface, 1, NULL, wm_bind);
    if (wl_display_add_socket(server, SOCKNAME) != 0) { w("xdg-fail-socket\n"); return 1; }

    pid_t pid = fork();
    if (pid < 0) { w("xdg-fail-fork\n"); return 1; }
    if (pid == 0) { _exit(run_client()); }

    struct wl_event_loop *loop = wl_display_get_event_loop(server);
    int st = 0;
    for (int i = 0; i < 800; i++) {
        wl_event_loop_dispatch(loop, 50);
        wl_display_flush_clients(server);
        if (waitpid(pid, &st, WNOHANG) == pid) break;
    }

    if (!mapped_ok) { w("xdg-fail-nomap\n"); return 1; }
    if (fb[0] != CLIENT_PIXEL) { w("xdg-fail-pixel\n"); return 1; }
    char b[80];
    int n = snprintf(b, sizeof b, "xdg-ok %dx%d px=%08x\n", fb_w, fb_h, fb[0]);
    write(1, b, n);
    return 0;
}
