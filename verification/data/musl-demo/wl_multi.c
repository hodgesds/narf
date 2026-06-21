/* Multi-window Wayland on NARF — a compositor serving two independent
 * client processes at once.
 *
 * The parent is a compositor; it forks TWO separate client processes. Each
 * connects over the named wl socket, paints a buffer in its own colour, and
 * commits. The compositor assigns each surface a screen slot (by creation
 * order) and blits it there — so two apps' windows appear side by side on
 * /dev/fb0. Proves the compositor handles concurrent clients (multiple
 * connections / memfds / cross-process fd-passing), the hallmark of a
 * desktop running more than one app.
 *
 * Prints `multi-ok WxH a=<px> b=<px>` once both clients' pixels have landed
 * at their slots.
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
#define SOCKNAME "wayland-multi"
#define SLOT_W 200 /* horizontal stride between window slots */

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
struct surf { struct wl_resource *pending; int slot_x; };
static int next_slot = 0;     /* x offset assigned to the next surface */
static int committed_count = 0;

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
        for (int x = 0; x < bw && (x + s->slot_x) < fb_w; x++)
            fb[y * fb_w + (x + s->slot_x)] = src[y * bstride + x];
    wl_shm_buffer_end_access(shm);
    committed_count++;
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
    s->slot_x = next_slot * SLOT_W; /* place each new window in the next slot */
    next_slot++;
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

static int run_client(uint32_t colour) {
    struct wl_display *d = NULL;
    for (int i = 0; i < 200 && !d; i++) { d = wl_display_connect(SOCKNAME); if (!d) usleep(20000); }
    if (!d) return 11;
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
    for (int i = 0; i < W * H; i++) px[i] = colour;
    struct wl_shm_pool *pool = wl_shm_create_pool(shm, mfd, W * H * 4);
    struct wl_buffer *buf = wl_shm_pool_create_buffer(pool, 0, W, H, W * 4, WL_SHM_FORMAT_XRGB8888);
    struct wl_surface *surf = wl_compositor_create_surface(comp);
    wl_surface_attach(surf, buf, 0, 0);
    wl_surface_commit(surf);
    wl_display_roundtrip(d);
    wl_display_roundtrip(d);
    return 0;
}

int main(void) {
    setenv("XDG_RUNTIME_DIR", "/tmp", 1);
    if (open_fb() != 0) { w("multi-fail-fb\n"); return 1; }

    struct wl_display *server = wl_display_create();
    if (!server) { w("multi-fail-create\n"); return 1; }
    if (wl_display_init_shm(server) != 0) { w("multi-fail-shm\n"); return 1; }
    wl_global_create(server, &wl_compositor_interface, 4, NULL, compositor_bind);
    if (wl_display_add_socket(server, SOCKNAME) != 0) { w("multi-fail-socket\n"); return 1; }

    /* Two independent client processes, distinct colours. */
    const uint32_t COL_A = 0x00C0FFEEu, COL_B = 0x00BADA55u;
    pid_t pa = fork();
    if (pa == 0) { _exit(run_client(COL_A)); }
    pid_t pb = fork();
    if (pb == 0) { _exit(run_client(COL_B)); }

    struct wl_event_loop *loop = wl_display_get_event_loop(server);
    int reaped = 0, st = 0;
    for (int i = 0; i < 1000 && (committed_count < 2 || reaped < 2); i++) {
        wl_event_loop_dispatch(loop, 50);
        wl_display_flush_clients(server);
        while (waitpid(-1, &st, WNOHANG) > 0) reaped++;
    }
    while (reaped < 2 && waitpid(-1, &st, 0) > 0) reaped++;

    if (committed_count < 2) { w("multi-fail-count\n"); return 1; }
    /* Both windows present: slot 0 at x=0, slot 1 at x=SLOT_W. The two colours
     * must both appear, one per slot (fork order isn't deterministic). */
    uint32_t s0 = fb[0], s1 = fb[SLOT_W];
    int ok = (s0 == COL_A && s1 == COL_B) || (s0 == COL_B && s1 == COL_A);
    if (!ok) { w("multi-fail-pixels\n"); return 1; }

    char b[96];
    int n = snprintf(b, sizeof b, "multi-ok %dx%d a=%08x b=%08x\n", fb_w, fb_h, s0, s1);
    write(1, b, n);
    return 0;
}
