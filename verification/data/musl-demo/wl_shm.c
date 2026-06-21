/* libwayland wl_shm buffer test for NARF.
 *
 * The real test of fd-passing THROUGH the Wayland protocol (not just a
 * raw socketpair): a client creates a memfd, hands it to the server via
 * wl_shm.create_pool — which marshals the fd over the socket using
 * SCM_RIGHTS — and the server mmaps it. If NARF's SCM_RIGHTS recvmsg +
 * memfd + mmap all work, create_pool succeeds with no protocol error.
 *
 * Flow (server + client in one process over a socketpair):
 *   server: wl_display_create + wl_display_init_shm (adds the wl_shm
 *           global + its format advertisement + create_pool handler).
 *   client: bind wl_shm, memfd_create + ftruncate + mmap + draw a pixel,
 *           wl_shm_create_pool(fd) + wl_shm_pool_create_buffer.
 *   verify: no wl_display error (server mmapped the pool) + a format
 *           event arrived → print "shm-ok".
 */
#define _GNU_SOURCE 1
#include <wayland-server-core.h>
#include <wayland-client-core.h>
#include "wayland-client-protocol.h"
#include "wayland-server-protocol.h"
#include <sys/socket.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

static uint32_t shm_name = 0, shm_ver = 0;
static int saw_format = 0;

static void reg_global(void *d, struct wl_registry *r, uint32_t name,
                       const char *iface, uint32_t ver) {
    (void)d; (void)r;
    if (strcmp(iface, "wl_shm") == 0) { shm_name = name; shm_ver = ver; }
}
static void reg_remove(void *d, struct wl_registry *r, uint32_t n) {
    (void)d; (void)r; (void)n;
}
static const struct wl_registry_listener reg_l = { reg_global, reg_remove };

static void shm_format(void *d, struct wl_shm *s, uint32_t fmt) {
    (void)d; (void)s; (void)fmt; saw_format = 1;
}
static const struct wl_shm_listener shm_l = { shm_format };

static void w(const char *s) { write(1, s, strlen(s)); }

/* one manual handshake round (single process, no threads) */
static void pump(struct wl_display *client, struct wl_event_loop *loop,
                 struct wl_display *server) {
    wl_display_flush(client);
    wl_event_loop_dispatch(loop, 0);
    wl_display_flush_clients(server);
    wl_display_dispatch(client);
}

int main(void) {
    struct wl_display *server = wl_display_create();
    if (!server) { w("shm-fail-create\n"); return 1; }
    if (wl_display_init_shm(server) != 0) { w("shm-fail-initshm\n"); return 1; }

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) { w("shm-fail-socketpair\n"); return 1; }
    if (!wl_client_create(server, fds[0])) { w("shm-fail-client\n"); return 1; }

    struct wl_display *client = wl_display_connect_to_fd(fds[1]);
    if (!client) { w("shm-fail-connect\n"); return 1; }
    struct wl_registry *reg = wl_display_get_registry(client);
    wl_registry_add_listener(reg, &reg_l, NULL);

    struct wl_event_loop *loop = wl_display_get_event_loop(server);
    pump(client, loop, server); /* enumerate globals */
    if (!shm_name) { w("shm-fail-noshm\n"); return 1; }

    struct wl_shm *shm = wl_registry_bind(reg, shm_name, &wl_shm_interface, shm_ver);
    wl_shm_add_listener(shm, &shm_l, NULL);

    int mfd = memfd_create("wlshm", 0);
    if (mfd < 0) { w("shm-fail-memfd\n"); return 1; }
    const int sz = 4096;
    if (ftruncate(mfd, sz) != 0) { w("shm-fail-ftruncate\n"); return 1; }
    uint32_t *px = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    if (px == MAP_FAILED) { w("shm-fail-mmap\n"); return 1; }
    px[0] = 0x00ABCDEFu;

    /* create_pool marshals `mfd` to the server over SCM_RIGHTS. */
    struct wl_shm_pool *pool = wl_shm_create_pool(shm, mfd, sz);
    struct wl_buffer *buf =
        wl_shm_pool_create_buffer(pool, 0, 1, 1, 4, WL_SHM_FORMAT_XRGB8888);
    (void)buf;

    pump(client, loop, server); /* bind + create_pool (+ fd) processed by server */

    if (wl_display_get_error(client) != 0) { w("shm-fail-protoerr\n"); return 1; }
    if (!saw_format) { w("shm-fail-noformat\n"); return 1; }
    w("shm-ok\n");
    return 0;
}
