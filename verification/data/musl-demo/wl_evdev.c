/* evdev → wl_seat bridge on NARF — real input hardware path to a window.
 *
 * Rung 9 (wl_input) proved the *Wayland* side: a compositor delivering
 * synthetic wl_keyboard events. This proves the *hardware* side: input that
 * originates as real Linux evdev records flowing through /dev/input/eventN
 * and being bridged into Wayland — exactly what a real compositor
 * (weston/sway via libinput) does.
 *
 * Because CI can't press a QEMU key, the compositor creates a virtual input
 * device via /dev/uinput (the same mechanism ydotool/wtype use) and injects
 * a KEY_A press/release into it. The kernel's evdev router delivers those as
 * 24-byte Linux input_event records on a freshly-created /dev/input/eventN;
 * the compositor READS that node (real evdev wire format), translates the
 * EV_KEY event, and forwards it over wl_keyboard to the mapped client. The
 * compositor does not care that the source is uinput rather than a USB
 * keyboard — the path is identical.
 *
 * Prints `evdev-ok WxH key=<n>` once the client confirms it received the
 * KEY_A (30) that round-tripped uinput → evdev → wl_keyboard.
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
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define FBIOGET_VSCREENINFO 0x4600
#define CLIENT_PIXEL 0x00C0FFEEu
#define SOCKNAME "wayland-evdev"
#define KEY_A 30
#define EV_SYN 0
#define EV_KEY 1
#define SYN_REPORT 0

/* uinput ioctls (_IOC dir<<30 | size<<16 | 'U'<<8 | nr) */
#define UI_DEV_CREATE   0x5501U          /* _IO('U', 1) */
#define UI_DEV_DESTROY  0x5502U          /* _IO('U', 2) */
#define UI_SET_EVBIT    0x40045564U      /* _IOW('U', 100, int) */
#define UI_SET_KEYBIT   0x40045565U      /* _IOW('U', 101, int) */

/* 24-byte Linux input_event (x86_64): 8+8 timeval, u16 type, u16 code, s32 value */
struct input_event { uint64_t sec, usec; uint16_t type, code; int32_t value; };

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

/* ── uinput virtual keyboard + evdev source ── */
static int ui_fd = -1, ev_fd = -1;

/* Snapshot the set of /dev/input/eventN minor numbers as a bitmask. */
static uint32_t snapshot_events(void) {
    uint32_t mask = 0;
    DIR *d = opendir("/dev/input");
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        int n;
        if (sscanf(e->d_name, "event%d", &n) == 1 && n >= 0 && n < 32) mask |= (1u << n);
    }
    closedir(d);
    return mask;
}

/* Create a uinput keyboard; open the resulting /dev/input/eventN. Returns 0 ok. */
static int uinput_setup(void) {
    uint32_t before = snapshot_events();
    ui_fd = open("/dev/uinput", O_RDWR);
    if (ui_fd < 0) return 1;
    if (ioctl(ui_fd, UI_SET_EVBIT, EV_KEY) != 0) return 2;
    if (ioctl(ui_fd, UI_SET_KEYBIT, KEY_A) != 0) return 3;
    if (ioctl(ui_fd, UI_DEV_CREATE, 0) != 0) return 4;
    /* Find the node that appeared. */
    uint32_t after = snapshot_events();
    uint32_t fresh = after & ~before;
    int n = -1;
    for (int i = 0; i < 32; i++) if (fresh & (1u << i)) { n = i; break; }
    if (n < 0) return 5;
    char path[32];
    snprintf(path, sizeof path, "/dev/input/event%d", n);
    ev_fd = open(path, O_RDONLY | O_NONBLOCK);
    if (ev_fd < 0) return 6;
    return 0;
}

/* Inject a KEY_A press+release into the uinput device. */
static void uinput_inject_key(int code) {
    struct input_event evs[4];
    memset(evs, 0, sizeof evs);
    evs[0].type = EV_KEY; evs[0].code = code; evs[0].value = 1;       /* press */
    evs[1].type = EV_SYN; evs[1].code = SYN_REPORT; evs[1].value = 0;
    evs[2].type = EV_KEY; evs[2].code = code; evs[2].value = 0;       /* release */
    evs[3].type = EV_SYN; evs[3].code = SYN_REPORT; evs[3].value = 0;
    (void)!write(ui_fd, evs, sizeof evs);
}

/* ───────────────────────── server (compositor) ───────────────────────── */

struct surf { struct wl_resource *pending, *xdg, *toplevel; int config_sent, configured; };
static int mapped_ok = 0, bridged = 0;
static uint32_t serial_ctr = 0;
static struct wl_display *g_server = NULL;
static struct wl_resource *g_kbd = NULL;

/* Read real evdev records off the uinput-backed node and forward EV_KEY
 * presses to the focused client over wl_keyboard. Returns the forwarded
 * keycode, or -1 if none seen. */
static int bridge_evdev_to_wayland(struct wl_resource *surface) {
    uinput_inject_key(KEY_A);            /* stand-in for a hardware keypress */
    int forwarded = -1;
    struct input_event ev;
    /* Drain whatever the evdev node has queued (a few non-blocking reads). */
    for (int tries = 0; tries < 64; tries++) {
        ssize_t n = read(ev_fd, &ev, sizeof ev);
        if (n != (ssize_t)sizeof ev) { usleep(2000); continue; }
        if (ev.type == EV_KEY && ev.value == 1) {
            if (g_kbd && forwarded < 0) {
                uint32_t serial = wl_display_next_serial(g_server);
                struct wl_array keys; wl_array_init(&keys);
                wl_keyboard_send_enter(g_kbd, serial, surface, &keys);
                wl_array_release(&keys);
                wl_keyboard_send_key(g_kbd, ++serial_ctr, 1, ev.code, WL_KEYBOARD_KEY_STATE_PRESSED);
                wl_keyboard_send_key(g_kbd, ++serial_ctr, 2, ev.code, WL_KEYBOARD_KEY_STATE_RELEASED);
                forwarded = (int)ev.code;
            }
            break;
        }
    }
    return forwarded;
}

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
    for (int y = 0; y < bh && y < fb_h; y++)
        for (int x = 0; x < bw && x < fb_w; x++)
            fb[y * fb_w + x] = src[y * bstride + x];
    wl_shm_buffer_end_access(shm);
    mapped_ok = 1;
    wl_buffer_send_release(s->pending);
    s->pending = NULL;
    if (!bridged) { int k = bridge_evdev_to_wayland(r); if (k == KEY_A) bridged = 1; }
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

/* wl_keyboard / wl_seat impls */
static void kbd_release(struct wl_client *c, struct wl_resource *r) { (void)c; wl_resource_destroy(r); }
static const struct wl_keyboard_interface keyboard_impl = { kbd_release };
static void seat_get_keyboard(struct wl_client *c, struct wl_resource *r, uint32_t id) {
    struct wl_resource *kr = wl_resource_create(c, &wl_keyboard_interface, wl_resource_get_version(r), id);
    wl_resource_set_implementation(kr, &keyboard_impl, NULL, NULL);
    g_kbd = kr;
    int kfd = memfd_create("keymap", 0);
    if (kfd >= 0) {
        const char km[] = "xkb_keymap { };\n";
        if (ftruncate(kfd, sizeof km) == 0 && write(kfd, km, sizeof km) == (ssize_t)sizeof km)
            wl_keyboard_send_keymap(kr, WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1, kfd, sizeof km);
        close(kfd);
    }
}
static void seat_get_pointer(struct wl_client *c, struct wl_resource *r, uint32_t id) { (void)c; (void)r; (void)id; }
static void seat_get_touch(struct wl_client *c, struct wl_resource *r, uint32_t id) { (void)c; (void)r; (void)id; }
static void seat_release(struct wl_client *c, struct wl_resource *r) { (void)c; wl_resource_destroy(r); }
static const struct wl_seat_interface seat_impl = {
    seat_get_pointer, seat_get_keyboard, seat_get_touch, seat_release,
};
static void seat_bind(struct wl_client *c, void *data, uint32_t ver, uint32_t id) {
    (void)data;
    struct wl_resource *r = wl_resource_create(c, &wl_seat_interface, ver, id);
    wl_resource_set_implementation(r, &seat_impl, NULL, NULL);
    wl_seat_send_capabilities(r, WL_SEAT_CAPABILITY_KEYBOARD);
    if (ver >= WL_SEAT_NAME_SINCE_VERSION) wl_seat_send_name(r, "narf-evdev0");
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

static int cl_acked = 0, cl_key = -1;
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
static void kl_keymap(void *d, struct wl_keyboard *k, uint32_t fmt, int32_t fd, uint32_t size)
{ (void)d; (void)k; (void)fmt; (void)size; if (fd >= 0) close(fd); }
static void kl_enter(void *d, struct wl_keyboard *k, uint32_t serial, struct wl_surface *s, struct wl_array *keys)
{ (void)d; (void)k; (void)serial; (void)s; (void)keys; }
static void kl_leave(void *d, struct wl_keyboard *k, uint32_t serial, struct wl_surface *s)
{ (void)d; (void)k; (void)serial; (void)s; }
static void kl_key(void *d, struct wl_keyboard *k, uint32_t serial, uint32_t time, uint32_t key, uint32_t state) {
    (void)d; (void)k; (void)serial; (void)time;
    if (state == WL_KEYBOARD_KEY_STATE_PRESSED) cl_key = (int)key;
}
static void kl_mods(void *d, struct wl_keyboard *k, uint32_t serial, uint32_t md, uint32_t ml, uint32_t lo, uint32_t g)
{ (void)d; (void)k; (void)serial; (void)md; (void)ml; (void)lo; (void)g; }
static void kl_repeat(void *d, struct wl_keyboard *k, int32_t rate, int32_t delay)
{ (void)d; (void)k; (void)rate; (void)delay; }
static const struct wl_keyboard_listener kbd_listener = {
    kl_keymap, kl_enter, kl_leave, kl_key, kl_mods, kl_repeat,
};
static void sl_caps(void *d, struct wl_seat *seat, uint32_t caps) {
    (void)d;
    if (caps & WL_SEAT_CAPABILITY_KEYBOARD) {
        struct wl_keyboard *kbd = wl_seat_get_keyboard(seat);
        wl_keyboard_add_listener(kbd, &kbd_listener, NULL);
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
    wl_display_roundtrip(d);

    struct wl_surface *surf = wl_compositor_create_surface(comp);
    struct xdg_surface *xsurf = xdg_wm_base_get_xdg_surface(wm, surf);
    xdg_surface_add_listener(xsurf, &xsurf_listener, NULL);
    struct xdg_toplevel *top = xdg_surface_get_toplevel(xsurf);
    xdg_toplevel_add_listener(top, &top_listener, NULL);
    xdg_toplevel_set_title(top, "narf-evdev");
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
    for (int i = 0; i < 400 && cl_key < 0; i++) if (wl_display_dispatch(d) < 0) break;
    if (cl_key != KEY_A) return 16;
    return 0;
}

int main(void) {
    setenv("XDG_RUNTIME_DIR", "/tmp", 1);
    if (open_fb() != 0) { w("evdev-fail-fb\n"); return 1; }
    int urc = uinput_setup();
    if (urc != 0) { char b[48]; int n = snprintf(b, sizeof b, "evdev-fail-uinput-%d\n", urc); write(1, b, n); return 1; }

    struct wl_display *server = wl_display_create();
    if (!server) { w("evdev-fail-create\n"); return 1; }
    g_server = server;
    if (wl_display_init_shm(server) != 0) { w("evdev-fail-shm\n"); return 1; }
    wl_global_create(server, &wl_compositor_interface, 4, NULL, compositor_bind);
    wl_global_create(server, &xdg_wm_base_interface, 1, NULL, wm_bind);
    wl_global_create(server, &wl_seat_interface, 5, NULL, seat_bind);
    if (wl_display_add_socket(server, SOCKNAME) != 0) { w("evdev-fail-socket\n"); return 1; }

    pid_t pid = fork();
    if (pid < 0) { w("evdev-fail-fork\n"); return 1; }
    if (pid == 0) { _exit(run_client()); }

    struct wl_event_loop *loop = wl_display_get_event_loop(server);
    int st = 0, rc = -1;
    for (int i = 0; i < 1200; i++) {
        wl_event_loop_dispatch(loop, 50);
        wl_display_flush_clients(server);
        if (waitpid(pid, &st, WNOHANG) == pid) { rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1; break; }
    }

    if (!mapped_ok) { w("evdev-fail-nomap\n"); return 1; }
    if (!bridged) { w("evdev-fail-nobridge\n"); return 1; }
    if (rc != 0) { w("evdev-fail-client\n"); return 1; }
    char b[80];
    int n = snprintf(b, sizeof b, "evdev-ok %dx%d key=%d\n", fb_w, fb_h, KEY_A);
    write(1, b, n);
    return 0;
}
