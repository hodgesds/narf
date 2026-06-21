/* wl_seat input delivery on NARF — a window that *responds*.
 *
 * A drawn window is useless if it can't receive input. Real toolkits bind
 * wl_seat, then wl_keyboard / wl_pointer, and the compositor delivers input
 * events (keymap, enter, key, modifiers, motion, button) to the focused
 * surface. This proves NARF runs that server→client input path end to end.
 *
 * fork(): the parent is a compositor advertising wl_compositor, wl_shm,
 * xdg_wm_base AND wl_seat (keyboard+pointer). The child maps an xdg_toplevel
 * (the Rung-8 sequence) and binds wl_keyboard/wl_pointer. Once the window is
 * mapped + composited, the compositor synthesises a keypress and a pointer
 * click on it:
 *
 *   keymap(fd) → keyboard.enter(surface) → key(KEY_A, pressed) → key(released)
 *   pointer.enter(surface) → motion → button(BTN_LEFT, pressed) → frame
 *
 * The client records the key it received. The keymap fd travels compositor→
 * client over the socket, exercising SCM_RIGHTS in the *reverse* direction
 * from wl_shm (which went client→compositor).
 *
 * The parent prints `input-ok WxH key=<n>` once the child confirms it
 * received the synthetic KEY_A (30) press on its mapped window.
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
#define SOCKNAME "wayland-input"
#define KEY_A 30          /* Linux input keycode */
#define BTN_LEFT 0x110

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

struct surf {
    struct wl_resource *pending, *xdg, *toplevel;
    int config_sent, configured;
};
static int mapped_ok = 0, input_sent = 0;
static uint32_t serial_ctr = 0;
static struct wl_display *g_server = NULL;
static struct wl_resource *g_kbd = NULL, *g_ptr = NULL;

/* Deliver a synthetic keypress + click to the just-mapped surface. */
static void deliver_input(struct wl_resource *surface) {
    if (input_sent) return;
    uint32_t serial = wl_display_next_serial(g_server);
    if (g_kbd) {
        struct wl_array keys;
        wl_array_init(&keys);
        wl_keyboard_send_enter(g_kbd, serial, surface, &keys);
        wl_array_release(&keys);
        wl_keyboard_send_key(g_kbd, ++serial_ctr, 1, KEY_A, WL_KEYBOARD_KEY_STATE_PRESSED);
        wl_keyboard_send_modifiers(g_kbd, ++serial_ctr, 0, 0, 0, 0);
        wl_keyboard_send_key(g_kbd, ++serial_ctr, 2, KEY_A, WL_KEYBOARD_KEY_STATE_RELEASED);
    }
    if (g_ptr) {
        wl_pointer_send_enter(g_ptr, ++serial_ctr, surface, wl_fixed_from_int(10), wl_fixed_from_int(10));
        wl_pointer_send_motion(g_ptr, 3, wl_fixed_from_int(12), wl_fixed_from_int(12));
        wl_pointer_send_button(g_ptr, ++serial_ctr, 4, BTN_LEFT, WL_POINTER_BUTTON_STATE_PRESSED);
        wl_pointer_send_frame(g_ptr);
    }
    input_sent = 1;
}

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
    deliver_input(r); /* window is up — give it the focus + a keypress */
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

/* xdg_toplevel / xdg_surface / xdg_wm_base impls (same as Rung 8) */
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

/* wl_keyboard / wl_pointer / wl_seat impls */
static void kbd_release(struct wl_client *c, struct wl_resource *r) { (void)c; wl_resource_destroy(r); }
static const struct wl_keyboard_interface keyboard_impl = { kbd_release };
static void ptr_set_cursor(struct wl_client *c, struct wl_resource *r, uint32_t s, struct wl_resource *sf, int32_t x, int32_t y)
{ (void)c; (void)r; (void)s; (void)sf; (void)x; (void)y; }
static void ptr_release(struct wl_client *c, struct wl_resource *r) { (void)c; wl_resource_destroy(r); }
static const struct wl_pointer_interface pointer_impl = { ptr_set_cursor, ptr_release };

static void seat_get_keyboard(struct wl_client *c, struct wl_resource *r, uint32_t id) {
    struct wl_resource *kr = wl_resource_create(c, &wl_keyboard_interface, wl_resource_get_version(r), id);
    wl_resource_set_implementation(kr, &keyboard_impl, NULL, NULL);
    g_kbd = kr;
    /* Send a (placeholder) keymap fd straight away — this fd travels
     * compositor→client over the socket (SCM_RIGHTS, reverse direction). */
    int kfd = memfd_create("keymap", 0);
    if (kfd >= 0) {
        const char km[] = "xkb_keymap { };\n";
        if (ftruncate(kfd, sizeof km) == 0 && write(kfd, km, sizeof km) == (ssize_t)sizeof km)
            wl_keyboard_send_keymap(kr, WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1, kfd, sizeof km);
        close(kfd);
    }
}
static void seat_get_pointer(struct wl_client *c, struct wl_resource *r, uint32_t id) {
    struct wl_resource *pr = wl_resource_create(c, &wl_pointer_interface, wl_resource_get_version(r), id);
    wl_resource_set_implementation(pr, &pointer_impl, NULL, NULL);
    g_ptr = pr;
}
static void seat_get_touch(struct wl_client *c, struct wl_resource *r, uint32_t id) { (void)c; (void)r; (void)id; }
static void seat_release(struct wl_client *c, struct wl_resource *r) { (void)c; wl_resource_destroy(r); }
static const struct wl_seat_interface seat_impl = {
    seat_get_pointer, seat_get_keyboard, seat_get_touch, seat_release,
};
static void seat_bind(struct wl_client *c, void *data, uint32_t ver, uint32_t id) {
    (void)data;
    struct wl_resource *r = wl_resource_create(c, &wl_seat_interface, ver, id);
    wl_resource_set_implementation(r, &seat_impl, NULL, NULL);
    wl_seat_send_capabilities(r, WL_SEAT_CAPABILITY_KEYBOARD | WL_SEAT_CAPABILITY_POINTER);
    if (ver >= WL_SEAT_NAME_SINCE_VERSION) wl_seat_send_name(r, "narf-seat0");
}

/* ───────────────────────────── client ───────────────────────────────── */

static uint32_t comp_name = 0, comp_ver = 0, shm_name = 0, shm_ver = 0,
                wm_name = 0, wm_ver = 0, seat_name = 0, seat_ver = 0;
static void reg_global(void *d, struct wl_registry *r, uint32_t name, const char *iface, uint32_t ver) {
    (void)d; (void)r;
    if (!strcmp(iface, "wl_compositor")) { comp_name = name; comp_ver = ver; }
    else if (!strcmp(iface, "wl_shm")) { shm_name = name; shm_ver = ver; }
    else if (!strcmp(iface, "xdg_wm_base")) { wm_name = name; wm_ver = ver; }
    else if (!strcmp(iface, "wl_seat")) { seat_name = name; seat_ver = ver; }
}
static void reg_remove(void *d, struct wl_registry *r, uint32_t n) { (void)d; (void)r; (void)n; }
static const struct wl_registry_listener reg_l = { reg_global, reg_remove };

static int cl_acked = 0, cl_got_keymap = 0, cl_got_enter = 0, cl_key = -1, cl_key_state = -1, cl_got_button = 0;

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

/* keyboard listener — the point of the test */
static void kl_keymap(void *d, struct wl_keyboard *k, uint32_t fmt, int32_t fd, uint32_t size) {
    (void)d; (void)k; (void)fmt; (void)size;
    if (fd >= 0) { cl_got_keymap = 1; close(fd); } /* received the fd over the socket */
}
static void kl_enter(void *d, struct wl_keyboard *k, uint32_t serial, struct wl_surface *s, struct wl_array *keys)
{ (void)d; (void)k; (void)serial; (void)s; (void)keys; cl_got_enter = 1; }
static void kl_leave(void *d, struct wl_keyboard *k, uint32_t serial, struct wl_surface *s)
{ (void)d; (void)k; (void)serial; (void)s; }
static void kl_key(void *d, struct wl_keyboard *k, uint32_t serial, uint32_t time, uint32_t key, uint32_t state) {
    (void)d; (void)k; (void)serial; (void)time;
    if (state == WL_KEYBOARD_KEY_STATE_PRESSED) { cl_key = (int)key; cl_key_state = (int)state; }
}
static void kl_mods(void *d, struct wl_keyboard *k, uint32_t serial, uint32_t md, uint32_t ml, uint32_t lo, uint32_t g)
{ (void)d; (void)k; (void)serial; (void)md; (void)ml; (void)lo; (void)g; }
static void kl_repeat(void *d, struct wl_keyboard *k, int32_t rate, int32_t delay)
{ (void)d; (void)k; (void)rate; (void)delay; }
static const struct wl_keyboard_listener kbd_listener = {
    kl_keymap, kl_enter, kl_leave, kl_key, kl_mods, kl_repeat,
};

/* pointer listener */
static void pl_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y)
{ (void)d; (void)p; (void)s; (void)sf; (void)x; (void)y; }
static void pl_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf) { (void)d; (void)p; (void)s; (void)sf; }
static void pl_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y) { (void)d; (void)p; (void)t; (void)x; (void)y; }
static void pl_button(void *d, struct wl_pointer *p, uint32_t s, uint32_t t, uint32_t b, uint32_t st) {
    (void)d; (void)p; (void)s; (void)t; (void)b;
    if (st == WL_POINTER_BUTTON_STATE_PRESSED) cl_got_button = 1;
}
static void pl_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t a, wl_fixed_t v) { (void)d; (void)p; (void)t; (void)a; (void)v; }
static void pl_frame(void *d, struct wl_pointer *p) { (void)d; (void)p; }
static void pl_axis_source(void *d, struct wl_pointer *p, uint32_t s) { (void)d; (void)p; (void)s; }
static void pl_axis_stop(void *d, struct wl_pointer *p, uint32_t t, uint32_t a) { (void)d; (void)p; (void)t; (void)a; }
static void pl_axis_disc(void *d, struct wl_pointer *p, uint32_t a, int32_t v) { (void)d; (void)p; (void)a; (void)v; }
static void pl_axis_v120(void *d, struct wl_pointer *p, uint32_t a, int32_t v) { (void)d; (void)p; (void)a; (void)v; }
static void pl_axis_dir(void *d, struct wl_pointer *p, uint32_t a, uint32_t dir) { (void)d; (void)p; (void)a; (void)dir; }
static const struct wl_pointer_listener ptr_listener = {
    pl_enter, pl_leave, pl_motion, pl_button, pl_axis, pl_frame,
    pl_axis_source, pl_axis_stop, pl_axis_disc, pl_axis_v120, pl_axis_dir,
};

static void sl_caps(void *d, struct wl_seat *seat, uint32_t caps) {
    (void)d;
    if (caps & WL_SEAT_CAPABILITY_KEYBOARD) {
        struct wl_keyboard *kbd = wl_seat_get_keyboard(seat);
        wl_keyboard_add_listener(kbd, &kbd_listener, NULL);
    }
    if (caps & WL_SEAT_CAPABILITY_POINTER) {
        struct wl_pointer *ptr = wl_seat_get_pointer(seat);
        wl_pointer_add_listener(ptr, &ptr_listener, NULL);
    }
}
static void sl_name(void *d, struct wl_seat *seat, const char *name) { (void)d; (void)seat; (void)name; }
static const struct wl_seat_listener seat_listener = { sl_caps, sl_name };

static int run_client(void) {
    struct wl_display *d = NULL;
    for (int i = 0; i < 200 && !d; i++) { d = wl_display_connect(SOCKNAME); if (!d) usleep(20000); }
    if (!d) return 11;
    struct wl_registry *reg = wl_display_get_registry(d);
    wl_registry_add_listener(reg, &reg_l, NULL);
    wl_display_roundtrip(d);
    if (!comp_name || !shm_name || !wm_name || !seat_name) return 12;

    struct wl_compositor *comp = wl_registry_bind(reg, comp_name, &wl_compositor_interface, comp_ver);
    struct wl_shm *shm = wl_registry_bind(reg, shm_name, &wl_shm_interface, shm_ver);
    struct xdg_wm_base *wm = wl_registry_bind(reg, wm_name, &xdg_wm_base_interface, wm_ver);
    struct wl_seat *seat = wl_registry_bind(reg, seat_name, &wl_seat_interface, seat_ver);
    xdg_wm_base_add_listener(wm, &wm_listener, NULL);
    wl_seat_add_listener(seat, &seat_listener, NULL);
    wl_display_roundtrip(d); /* drives sl_caps → creates kbd/ptr + sends keymap */

    struct wl_surface *surf = wl_compositor_create_surface(comp);
    struct xdg_surface *xsurf = xdg_wm_base_get_xdg_surface(wm, surf);
    xdg_surface_add_listener(xsurf, &xsurf_listener, NULL);
    struct xdg_toplevel *top = xdg_surface_get_toplevel(xsurf);
    xdg_toplevel_add_listener(top, &top_listener, NULL);
    xdg_toplevel_set_title(top, "narf-input");
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
    wl_display_flush(d);

    /* Wait for the compositor to deliver the synthetic keypress. */
    for (int i = 0; i < 400 && cl_key < 0; i++) {
        if (wl_display_dispatch(d) < 0) break;
    }
    if (cl_key != KEY_A) return 16;
    return 0;
}

int main(void) {
    setenv("XDG_RUNTIME_DIR", "/tmp", 1);
    if (open_fb() != 0) { w("input-fail-fb\n"); return 1; }

    struct wl_display *server = wl_display_create();
    if (!server) { w("input-fail-create\n"); return 1; }
    g_server = server;
    if (wl_display_init_shm(server) != 0) { w("input-fail-shm\n"); return 1; }
    wl_global_create(server, &wl_compositor_interface, 4, NULL, compositor_bind);
    wl_global_create(server, &xdg_wm_base_interface, 1, NULL, wm_bind);
    wl_global_create(server, &wl_seat_interface, 5, NULL, seat_bind);
    if (wl_display_add_socket(server, SOCKNAME) != 0) { w("input-fail-socket\n"); return 1; }

    pid_t pid = fork();
    if (pid < 0) { w("input-fail-fork\n"); return 1; }
    if (pid == 0) { _exit(run_client()); }

    struct wl_event_loop *loop = wl_display_get_event_loop(server);
    int st = 0, rc = -1;
    for (int i = 0; i < 1000; i++) {
        wl_event_loop_dispatch(loop, 50);
        wl_display_flush_clients(server);
        if (waitpid(pid, &st, WNOHANG) == pid) { rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1; break; }
    }

    if (!mapped_ok) { w("input-fail-nomap\n"); return 1; }
    if (!input_sent) { w("input-fail-nosend\n"); return 1; }
    if (rc != 0) { w("input-fail-client\n"); return 1; }
    char b[80];
    int n = snprintf(b, sizeof b, "input-ok %dx%d key=%d\n", fb_w, fb_h, KEY_A);
    write(1, b, n);
    return 0;
}
