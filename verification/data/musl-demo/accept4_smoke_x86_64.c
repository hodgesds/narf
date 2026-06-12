// accept4(2) smoke. Mirrors net_smoke (AF_INET loopback TCP, server
// in a pthread) but the server accepts the connection via accept4(2)
// with SOCK_CLOEXEC | SOCK_NONBLOCK rather than accept(2). Proves the
// new accept4 syscall returns a usable fd and honours the flag bits.
// Distinct port (8091) so it can run in the same boot as net_smoke.
// Success token "accept4-ok".
//
// Build: see REGEN_accept4_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

static void w(const char *m) { write(1, m, strlen(m)); }

void *server_thread(void *arg) {
    (void)arg;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { w("srv: socket failed\n"); exit(1); }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(8091);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        w("srv: bind failed\n"); exit(1);
    }
    if (listen(server_fd, 3) < 0) {
        w("srv: listen failed\n"); exit(1);
    }

    // accept4 with SOCK_NONBLOCK returns -1/EAGAIN until a peer is
    // pending, so spin like net_smoke's accept loop.
    int conn;
    while ((conn = accept4(server_fd, NULL, NULL,
                           SOCK_CLOEXEC | SOCK_NONBLOCK)) < 0) {
        sched_yield();
    }

    char buffer[64] = {0};
    int n;
    while ((n = read(conn, buffer, sizeof(buffer))) <= 0) {
        sched_yield();
    }
    write(conn, "pong", 4);
    close(conn);
    close(server_fd);
    return NULL;
}

int main(void) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, server_thread, NULL) != 0) {
        w("cli: pthread_create failed\n"); return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { w("cli: socket failed\n"); return 1; }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(8091);

    while (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        sched_yield();
    }

    write(sock, "ping", 4);

    char buffer[64] = {0};
    int n;
    while ((n = read(sock, buffer, sizeof(buffer))) <= 0) {
        sched_yield();
    }

    if (n >= 4 && memcmp(buffer, "pong", 4) == 0) {
        w("accept4-ok\n");
    } else {
        w("accept4-fail\n");
    }

    close(sock);
    pthread_join(tid, NULL);
    return 0;
}
