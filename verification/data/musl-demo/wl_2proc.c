/* Two-process Wayland on NARF — the real desktop architecture.
 *
 * fork(): the parent is a compositor (named wl socket + event loop) that
 * blits a client's wl_shm buffer onto /dev/fb0; the child is an INDEPENDENT
 * client process that connects by socket name, paints a buffer, and commits.
 * Unlike the single-process socketpair tests, this exercises:
 *   - named AF_UNIX bind/listen/accept/connect-by-path,
 *   - TRUE cross-process SCM_RIGHTS fd-passing (the memfd Arc moves between
 *     two separate fd tables / address spaces),
 *   - a real compositor event loop serving an external client.
 *
 * The parent prints `2proc-ok WxH px=<colour>` once the child's pixel lands
 * on the framebuffer.
 */
#define _GNU_SOURCE 1
#include <wayland-server-core.h>
#include <wayland-client-core.h>
#include "wayland-client-protocol.h"
#include "wayland-server-protocol.h"
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
#define SOCKNAME "wayland-narf"

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

/* ── server surface impl ── */
struct surf { struct wl_resource *pending; };
static int composited = 0;
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
    composited = 1;
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

/* ── child = client ── */
static uint32_t comp_name = 0, comp_ver = 0, shm_name = 0, shm_ver = 0;
static void reg_global(void *d, struct wl_registry *r, uint32_t name, const char *iface, uint32_t ver) {
    (void)d; (void)r;
    if (!strcmp(iface, "wl_compositor")) { comp_name = name; comp_ver = ver; }
    else if (!strcmp(iface, "wl_shm")) { shm_name = name; shm_ver = ver; }
}
static void reg_remove(void *d, struct wl_registry *r, uint32_t n) { (void)d; (void)r; (void)n; }
static const struct wl_registry_listener reg_l = { reg_global, reg_remove };

static int run_client(void) {
    struct wl_display *d = NULL;
    for (int i = 0; i < 200 && !d; i++) { d = wl_display_connect(SOCKNAME); if (!d) usleep(20000); }
    if (!d) { w("c-noconn\n"); return 11; }
    struct wl_registry *reg = wl_display_get_registry(d);
    wl_registry_add_listener(reg, &reg_l, NULL);
    wl_display_roundtrip(d);
    if (!comp_name || !shm_name) return 12;
    struct wl_compositor *comp = wl_registry_bind(reg, comp_name, &wl_compositor_interface, comp_ver);
    struct wl_shm *shm = wl_registry_bind(reg, shm_name, &wl_shm_interface, shm_ver);
    const int W = 64, H = 64;
    int mfd = memfd_create("c", 0);
    if (mfd < 0 || ftruncate(mfd, W * H * 4) != 0) return 13;
    uint32_t *px = mmap(0, W * H * 4, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    if (px == MAP_FAILED) return 14;
    for (int i = 0; i < W * H; i++) px[i] = CLIENT_PIXEL;
    struct wl_shm_pool *pool = wl_shm_create_pool(shm, mfd, W * H * 4);
    struct wl_buffer *buf = wl_shm_pool_create_buffer(pool, 0, W, H, W * 4, WL_SHM_FORMAT_XRGB8888);
    struct wl_surface *surf = wl_compositor_create_surface(comp);
    wl_surface_attach(surf, buf, 0, 0);
    wl_surface_commit(surf);
    wl_display_roundtrip(d); /* ensure commit reaches the server */
    wl_display_roundtrip(d); /* drain buffer.release */
    return 0;
}

int main(void) {
    setenv("XDG_RUNTIME_DIR", "/tmp", 1);
    if (open_fb() != 0) { w("2proc-fail-fb\n"); return 1; }

    struct wl_display *server = wl_display_create();
    if (!server) { w("2proc-fail-create\n"); return 1; }
    if (wl_display_init_shm(server) != 0) { w("2proc-fail-shm\n"); return 1; }
    wl_global_create(server, &wl_compositor_interface, 4, NULL, compositor_bind);
    if (wl_display_add_socket(server, SOCKNAME) != 0) { w("2proc-fail-socket\n"); return 1; }

    pid_t pid = fork();
    if (pid < 0) { w("2proc-fail-fork\n"); return 1; }
    if (pid == 0) { _exit(run_client()); }

    // Serve the event loop until the client disconnects — a real compositor
    // keeps dispatching, not just until the first frame. Stopping at the
    // first commit would strand the client's post-commit roundtrips.
    struct wl_event_loop *loop = wl_display_get_event_loop(server);
    int st = 0;
    for (int i = 0; i < 600; i++) {
        wl_event_loop_dispatch(loop, 50);
        wl_display_flush_clients(server);
        if (waitpid(pid, &st, WNOHANG) == pid) break;
    }

    if (!composited) { w("2proc-fail-nocommit\n"); return 1; }
    if (fb[0] != CLIENT_PIXEL) { w("2proc-fail-pixel\n"); return 1; }
    char b[80];
    int n = snprintf(b, sizeof b, "2proc-ok %dx%d px=%08x\n", fb_w, fb_h, fb[0]);
    write(1, b, n);
    return 0;
}
