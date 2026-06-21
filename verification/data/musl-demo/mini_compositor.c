/* Minimal Wayland compositor on NARF — the convergence of the rungs.
 *
 * A real (if tiny) compositor: a wl_display server exposing wl_compositor +
 * wl_surface + wl_shm, whose surface-commit handler reads the client's
 * shared pixel buffer and BLITS IT ONTO /dev/fb0 (the live scanout from
 * Rung 1). An embedded client (over a socketpair) creates a wl_shm buffer
 * filled with a known colour, attaches it to a surface, and commits.
 *
 * This ties together: AF_UNIX + SCM_RIGHTS fd-passing, the libwayland wire
 * protocol, wl_shm buffer sharing, and the framebuffer. The first composited
 * Wayland frame on NARF's display.
 *
 * Verified without a screendump: after the commit the compositor reads the
 * pixel back out of /dev/fb0 and confirms it matches what the client drew.
 */
#define _GNU_SOURCE 1
#include <wayland-server-core.h>
#include <wayland-client-core.h>
#include "wayland-client-protocol.h"
#include "wayland-server-protocol.h"
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define FBIOGET_VSCREENINFO 0x4600
#define CLIENT_PIXEL 0x00C0FFEEu

static uint32_t *fb = NULL;
static int fb_w = 0, fb_h = 0;
static size_t fb_len = 0;

static void w(const char *s) { write(1, s, strlen(s)); }

static int open_fb(void) {
    int fd = open("/dev/fb0", O_RDWR);
    if (fd < 0) return -1;
    uint32_t v[40];
    memset(v, 0, sizeof v);
    if (ioctl(fd, FBIOGET_VSCREENINFO, v) != 0) return -1;
    fb_w = v[0]; fb_h = v[1];
    if (fb_w == 0 || fb_h == 0) return -1;
    fb_len = ((size_t)fb_w * fb_h * 4 + 0xFFF) & ~(size_t)0xFFF;
    fb = mmap(0, fb_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    return fb == MAP_FAILED ? -1 : 0;
}

/* ── server-side surface ── */
struct surf { struct wl_resource *pending_buffer; };
static int composited = 0;
static uint32_t got_pixel = 0;

static void su_destroy(struct wl_client *c, struct wl_resource *r) { (void)c; wl_resource_destroy(r); }
static void su_attach(struct wl_client *c, struct wl_resource *r, struct wl_resource *buf,
                      int32_t x, int32_t y) {
    (void)c; (void)x; (void)y;
    ((struct surf *)wl_resource_get_user_data(r))->pending_buffer = buf;
}
static void su_damage(struct wl_client *c, struct wl_resource *r, int32_t a, int32_t b, int32_t cc, int32_t d)
{ (void)c; (void)r; (void)a; (void)b; (void)cc; (void)d; }
static void su_frame(struct wl_client *c, struct wl_resource *r, uint32_t cb) { (void)c; (void)r; (void)cb; }
static void su_setopaque(struct wl_client *c, struct wl_resource *r, struct wl_resource *reg)
{ (void)c; (void)r; (void)reg; }
static void su_setinput(struct wl_client *c, struct wl_resource *r, struct wl_resource *reg)
{ (void)c; (void)r; (void)reg; }
static void su_commit(struct wl_client *c, struct wl_resource *r) {
    (void)c;
    struct surf *s = wl_resource_get_user_data(r);
    if (!s->pending_buffer) return;
    struct wl_shm_buffer *shm = wl_shm_buffer_get(s->pending_buffer);
    if (!shm) return;
    wl_shm_buffer_begin_access(shm);
    uint32_t *src = wl_shm_buffer_get_data(shm);
    int bw = wl_shm_buffer_get_width(shm), bh = wl_shm_buffer_get_height(shm);
    int bstride = wl_shm_buffer_get_stride(shm) / 4;
    for (int y = 0; y < bh && y < fb_h; y++)
        for (int x = 0; x < bw && x < fb_w; x++)
            fb[y * fb_w + x] = src[y * bstride + x];
    wl_shm_buffer_end_access(shm);
    got_pixel = fb[0];
    composited = 1;
    wl_buffer_send_release(s->pending_buffer);
    s->pending_buffer = NULL;
}
static void su_settransform(struct wl_client *c, struct wl_resource *r, int32_t t) { (void)c; (void)r; (void)t; }
static void su_setscale(struct wl_client *c, struct wl_resource *r, int32_t sc) { (void)c; (void)r; (void)sc; }
static void su_damagebuffer(struct wl_client *c, struct wl_resource *r, int32_t a, int32_t b, int32_t cc, int32_t d)
{ (void)c; (void)r; (void)a; (void)b; (void)cc; (void)d; }
static void su_offset(struct wl_client *c, struct wl_resource *r, int32_t x, int32_t y)
{ (void)c; (void)r; (void)x; (void)y; }

static const struct wl_surface_interface surface_impl = {
    su_destroy, su_attach, su_damage, su_frame, su_setopaque, su_setinput,
    su_commit, su_settransform, su_setscale, su_damagebuffer, su_offset,
};
static void surf_destroy(struct wl_resource *r) { free(wl_resource_get_user_data(r)); }

static void co_create_surface(struct wl_client *c, struct wl_resource *r, uint32_t id) {
    struct surf *s = calloc(1, sizeof *s);
    struct wl_resource *sr =
        wl_resource_create(c, &wl_surface_interface, wl_resource_get_version(r), id);
    wl_resource_set_implementation(sr, &surface_impl, s, surf_destroy);
}
static void co_create_region(struct wl_client *c, struct wl_resource *r, uint32_t id)
{ (void)c; (void)r; (void)id; }
static const struct wl_compositor_interface compositor_impl = { co_create_surface, co_create_region };
static void compositor_bind(struct wl_client *c, void *data, uint32_t ver, uint32_t id) {
    (void)data;
    struct wl_resource *r = wl_resource_create(c, &wl_compositor_interface, ver, id);
    wl_resource_set_implementation(r, &compositor_impl, NULL, NULL);
}

/* ── embedded client ── */
static uint32_t comp_name = 0, comp_ver = 0, shm_name = 0, shm_ver = 0;
static void reg_global(void *d, struct wl_registry *r, uint32_t name, const char *iface, uint32_t ver) {
    (void)d; (void)r;
    if (!strcmp(iface, "wl_compositor")) { comp_name = name; comp_ver = ver; }
    else if (!strcmp(iface, "wl_shm")) { shm_name = name; shm_ver = ver; }
}
static void reg_remove(void *d, struct wl_registry *r, uint32_t n) { (void)d; (void)r; (void)n; }
static const struct wl_registry_listener reg_l = { reg_global, reg_remove };

static void pump(struct wl_display *cl, struct wl_event_loop *loop, struct wl_display *sv) {
    wl_display_flush(cl);
    wl_event_loop_dispatch(loop, 0);
    wl_display_flush_clients(sv);
    wl_display_dispatch(cl);
}

int main(void) {
    if (open_fb() != 0) { w("comp-fail-fb\n"); return 1; }

    struct wl_display *server = wl_display_create();
    if (!server) { w("comp-fail-create\n"); return 1; }
    if (wl_display_init_shm(server) != 0) { w("comp-fail-shm\n"); return 1; }
    wl_global_create(server, &wl_compositor_interface, 4, NULL, compositor_bind);

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) { w("comp-fail-sp\n"); return 1; }
    if (!wl_client_create(server, fds[0])) { w("comp-fail-client\n"); return 1; }

    struct wl_display *client = wl_display_connect_to_fd(fds[1]);
    if (!client) { w("comp-fail-connect\n"); return 1; }
    struct wl_registry *reg = wl_display_get_registry(client);
    wl_registry_add_listener(reg, &reg_l, NULL);
    struct wl_event_loop *loop = wl_display_get_event_loop(server);

    pump(client, loop, server);
    if (!comp_name || !shm_name) { w("comp-fail-noglobals\n"); return 1; }

    struct wl_compositor *comp = wl_registry_bind(reg, comp_name, &wl_compositor_interface, comp_ver);
    struct wl_shm *shm = wl_registry_bind(reg, shm_name, &wl_shm_interface, shm_ver);

    const int W = 64, H = 64;
    int mfd = memfd_create("c", 0);
    if (mfd < 0 || ftruncate(mfd, W * H * 4) != 0) { w("comp-fail-memfd\n"); return 1; }
    uint32_t *cpx = mmap(0, W * H * 4, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    if (cpx == MAP_FAILED) { w("comp-fail-cmmap\n"); return 1; }
    for (int i = 0; i < W * H; i++) cpx[i] = CLIENT_PIXEL;

    struct wl_shm_pool *pool = wl_shm_create_pool(shm, mfd, W * H * 4);
    struct wl_buffer *buf = wl_shm_pool_create_buffer(pool, 0, W, H, W * 4, WL_SHM_FORMAT_XRGB8888);
    struct wl_surface *surf = wl_compositor_create_surface(comp);
    wl_surface_attach(surf, buf, 0, 0);
    wl_surface_commit(surf);

    /* One round drives bind + create_pool(+fd) + create_buffer + attach +
     * commit through the server (→ blit) and returns buffer.release to the
     * client. A second blocking dispatch would hang with nothing left to read. */
    pump(client, loop, server);

    if (wl_display_get_error(client) != 0) { w("comp-fail-protoerr\n"); return 1; }
    if (!composited) { w("comp-fail-nocommit\n"); return 1; }
    if (got_pixel != CLIENT_PIXEL || fb[0] != CLIENT_PIXEL) { w("comp-fail-pixel\n"); return 1; }

    char b[80];
    int n = snprintf(b, sizeof b, "comp-ok %dx%d px=%08x\n", fb_w, fb_h, fb[0]);
    write(1, b, n);
    return 0;
}
