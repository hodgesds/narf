/* A real unmodified toolkit client on NARF — weston-simple-shm.
 *
 * Every prior wl_* test embedded its own hand-written client. This runs an
 * ACTUAL off-the-shelf binary: weston 9.0's `simple-shm` (vendored verbatim
 * as /bin/simple_shm), linked against stock libwayland. It connects, binds
 * wl_compositor + wl_shm + xdg_wm_base, maps an xdg_toplevel, and renders an
 * animated checkerboard into a 250x250 wl_shm buffer — driven entirely by
 * upstream code with zero NARF awareness.
 *
 * This program is the compositor/launcher: it advertises the three globals
 * simple-shm needs, fork()s and execve()s /bin/simple_shm with WAYLAND_DISPLAY
 * pointed at our socket, sends the xdg_surface.configure that makes it draw,
 * answers frame callbacks so its animation loop runs, and composites its first
 * real frame onto /dev/fb0. Once a 250x250 buffer has landed it reports and
 * tears the client down (simple-shm otherwise loops forever).
 *
 * Prints `app-ok WxH win=AxB` once weston-simple-shm's window has been
 * composited (A×B = the client's actual surface size, proving a real toolkit
 * client mapped + rendered).
 */
#define _GNU_SOURCE 1
#include <wayland-server-core.h>
#include "wayland-server-protocol.h"
#include "xdg-shell-server-protocol.h"
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define FBIOGET_VSCREENINFO 0x4600
#define SOCKNAME "wayland-app"

extern char **environ;

static uint32_t *fb = NULL;
static int fb_w = 0, fb_h = 0;
static void w(const char *s) { write(1, s, strlen(s)); }

static int open_fb(void) {
    int fd = open("/dev/fb0", O_RDWR);
    if (fd < 0) return -1;
    uint32_t v[40]; memset(v, 0, sizeof v);
    if (ioctl(fd, FBIOGET_VSCREENINFO, v) != 0) return -1;
    fb_w = v[0]; fb_h = v[1];
    if (fb_w == 0 || fb_h == 0) return -1;
    size_t len = ((size_t)fb_w * fb_h * 4 + 0xFFF) & ~(size_t)0xFFF;
    fb = mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    return fb == MAP_FAILED ? -1 : 0;
}

/* ── compositor ── */
struct surf { struct wl_resource *pending, *xdg, *toplevel; int config_sent, configured; };
static int composited = 0, win_w = 0, win_h = 0;
static uint32_t serial_ctr = 0, frame_time = 1;

static void su_destroy(struct wl_client *c, struct wl_resource *r) { (void)c; wl_resource_destroy(r); }
static void su_attach(struct wl_client *c, struct wl_resource *r, struct wl_resource *b, int32_t x, int32_t y)
{ (void)c; (void)x; (void)y; ((struct surf *)wl_resource_get_user_data(r))->pending = b; }
static void su_nop4(struct wl_client *c, struct wl_resource *r, int32_t a, int32_t b, int32_t cc, int32_t d)
{ (void)c; (void)r; (void)a; (void)b; (void)cc; (void)d; }
/* frame: answer the callback so simple-shm's animation loop keeps running. */
static void su_frame(struct wl_client *c, struct wl_resource *r, uint32_t cb) {
    (void)r;
    struct wl_resource *cbr = wl_resource_create(c, &wl_callback_interface, 1, cb);
    wl_callback_send_done(cbr, ++frame_time);
    wl_resource_destroy(cbr);
}
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
    for (int y = 0; y < bh && y < fb_h; y++)
        for (int x = 0; x < bw && x < fb_w; x++)
            fb[y * fb_w + x] = src[y * bstride + x];
    wl_shm_buffer_end_access(shm);
    win_w = bw; win_h = bh;
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

/* xdg-shell server impl */
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

int main(void) {
    setenv("XDG_RUNTIME_DIR", "/tmp", 1);
    if (open_fb() != 0) { w("app-fail-fb\n"); return 1; }

    struct wl_display *server = wl_display_create();
    if (!server) { w("app-fail-create\n"); return 1; }
    if (wl_display_init_shm(server) != 0) { w("app-fail-shm\n"); return 1; }
    wl_global_create(server, &wl_compositor_interface, 4, NULL, compositor_bind);
    wl_global_create(server, &xdg_wm_base_interface, 1, NULL, wm_bind);
    if (wl_display_add_socket(server, SOCKNAME) != 0) { w("app-fail-socket\n"); return 1; }

    /* Launch the REAL unmodified weston-simple-shm against our socket. */
    pid_t pid = fork();
    if (pid < 0) { w("app-fail-fork\n"); return 1; }
    if (pid == 0) {
        setenv("WAYLAND_DISPLAY", SOCKNAME, 1);
        setenv("XDG_RUNTIME_DIR", "/tmp", 1);
        char *argv[] = { (char *)"/bin/simple_shm", NULL };
        execve("/bin/simple_shm", argv, environ);
        _exit(127);
    }

    struct wl_event_loop *loop = wl_display_get_event_loop(server);
    int st = 0;
    for (int i = 0; i < 1500 && !composited; i++) {
        wl_event_loop_dispatch(loop, 50);
        wl_display_flush_clients(server);
        if (waitpid(pid, &st, WNOHANG) == pid) break; /* client died early */
    }
    /* simple-shm loops forever; we have our frame — shut it down. */
    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);

    if (!composited) { w("app-fail-noframe\n"); return 1; }
    char b[96];
    int n = snprintf(b, sizeof b, "app-ok %dx%d win=%dx%d\n", fb_w, fb_h, win_w, win_h);
    write(1, b, n);
    return 0;
}
