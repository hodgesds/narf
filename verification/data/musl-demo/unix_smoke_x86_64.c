#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <errno.h>
#include <sched.h>

static void w(const char *msg) {
    write(1, msg, strlen(msg));
}

#define SOCK_PATH "/tmp/narf_unix_smoke.sock"

void *server_thread(void *arg) {
    w("srv: socket...\n");
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) { w("srv: socket failed\n"); exit(1); }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    unlink(SOCK_PATH);

    w("srv: bind...\n");
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        w("srv: bind failed\n"); exit(1);
    }

    w("srv: listen...\n");
    if (listen(server_fd, 3) < 0) {
        w("srv: listen failed\n"); exit(1);
    }

    w("srv: accept loop...\n");
    int new_socket;
    while ((new_socket = accept(server_fd, NULL, NULL)) < 0) {
        sched_yield();
    }
    w("srv: accepted\n");

    char buffer[1024] = {0};
    int valread;
    while ((valread = read(new_socket, buffer, sizeof(buffer))) <= 0) {
        sched_yield();
    }
    w("srv: read\n");
    
    write(new_socket, "pong", 4);
    w("srv: wrote\n");

    close(new_socket);
    close(server_fd);
    unlink(SOCK_PATH);
    return NULL;
}

int main() {
    w("cli: start\n");
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, server_thread, NULL) != 0) {
        w("cli: pthread_create failed\n"); return 1;
    }

    w("cli: socket...\n");
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        w("cli: socket failed\n"); return 1;
    }

    struct sockaddr_un serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    strncpy(serv_addr.sun_path, SOCK_PATH, sizeof(serv_addr.sun_path) - 1);

    w("cli: connect loop...\n");
    while (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        sched_yield();
    }
    w("cli: connected\n");

    write(sock, "ping", 4);
    w("cli: wrote\n");
    
    char buffer[1024] = {0};
    int valread;
    while ((valread = read(sock, buffer, sizeof(buffer))) <= 0) {
        sched_yield();
    }
    w("cli: read\n");
    
    if (valread > 0 && memcmp(buffer, "pong", 4) == 0) {
        w("unix-ok\n");
    } else {
        w("unix-fail\n");
    }

    close(sock);
    pthread_join(thread_id, NULL);
    return 0;
}
