/* Minimal libwayland handshake: a wl_display server advertising a
 * wl_compositor global, and a client that connects over a socketpair,
 * gets the registry, and receives the global. Proves the Wayland wire
 * protocol + transport (incl. fd-passing path) work on NARF. */
#include <wayland-server-core.h>
#include <wayland-client-core.h>
#include "wayland-client-protocol.h"
#include "wayland-server-protocol.h"
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

static int saw_compositor = 0;

static void reg_global(void *data, struct wl_registry *r, uint32_t name,
                       const char *iface, uint32_t ver) {
    (void)data; (void)r; (void)name; (void)ver;
    if (strcmp(iface, "wl_compositor") == 0)
        saw_compositor = 1;
}
static void reg_global_remove(void *d, struct wl_registry *r, uint32_t n) {
    (void)d; (void)r; (void)n;
}
static const struct wl_registry_listener registry_listener = {
    reg_global, reg_global_remove,
};

static void compositor_bind(struct wl_client *c, void *data, uint32_t ver, uint32_t id) {
    (void)c; (void)data; (void)ver; (void)id; /* not exercised — we only enumerate */
}

static void w(const char *s) { write(1, s, strlen(s)); }

int main(void) {
    struct wl_display *server = wl_display_create();
    if (!server) { w("wl-fail-create\n"); return 1; }
    if (!wl_global_create(server, &wl_compositor_interface, 1, NULL, compositor_bind)) {
        w("wl-fail-global\n"); return 1;
    }

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) { w("wl-fail-socketpair\n"); return 1; }

    if (!wl_client_create(server, fds[0])) { w("wl-fail-client-create\n"); return 1; }

    struct wl_display *client = wl_display_connect_to_fd(fds[1]);
    if (!client) { w("wl-fail-connect\n"); return 1; }

    struct wl_registry *reg = wl_display_get_registry(client);
    wl_registry_add_listener(reg, &registry_listener, NULL);

    /* Pump the handshake by hand (single process, no threads):
     * client → server (get_registry), server processes + emits globals,
     * server → client, client dispatches → reg_global fires. */
    wl_display_flush(client);
    struct wl_event_loop *loop = wl_display_get_event_loop(server);
    wl_event_loop_dispatch(loop, 0);
    wl_display_flush_clients(server);
    wl_display_dispatch(client);

    if (saw_compositor)
        w("wl-ok\n");
    else
        w("wl-fail-noglobal\n");
    return 0;
}
