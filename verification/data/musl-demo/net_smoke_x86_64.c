#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>

static void w(const char *msg) {
    write(1, msg, strlen(msg));
}

void *server_thread(void *arg) {
    w("srv: socket...\n");
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { w("srv: socket failed\n"); exit(1); }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(8080);

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
    return NULL;
}

int main() {
    w("cli: start\n");
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, server_thread, NULL) != 0) {
        w("cli: pthread_create failed\n"); return 1;
    }

    w("cli: socket...\n");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        w("cli: socket failed\n"); return 1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(8080);

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
        w("net-ok\n");
    } else {
        w("net-fail\n");
    }

    close(sock);
    pthread_join(thread_id, NULL);
    return 0;
}
