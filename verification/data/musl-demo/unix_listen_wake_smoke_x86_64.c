// A connect() to a listening AF_UNIX socket must wake a poller on it.
//
// kwin starts Xwayland on demand: it listens on the X11 sockets itself
// (/tmp/.X11-unix/X0 and the abstract @/tmp/.X11-unix/X0 that xcb tries first)
// and spawns Xwayland when a client connects, i.e. when a listening fd in its
// poll set becomes readable. If that connect does not wake the poller, X
// clients (xrdb, xprop) wait forever and the Plasma session never finishes
// starting.
//
//   address:  filesystem path, abstract namespace
//   waiter:   poll, ppoll, epoll_wait, with the listener among other fds
//   client:   another process, connect() only (no data), or connect()+write
//   timing:   connect before the waiter parks or while it is parked
//
// Success token "unix-listen-wake-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 10

static int make_addr(int abstract, const char *name, struct sockaddr_un *a) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    size_t n = strlen(name);
    if (abstract) {
        a->sun_path[0] = 0;
        memcpy(a->sun_path + 1, name, n);
        return (int)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
    }
    memcpy(a->sun_path, name, n + 1);
    return (int)(offsetof(struct sockaddr_un, sun_path) + n + 1);
}

// Wait up to 2 s for `lfd` (with two idle fds alongside) to be readable.
static int wait_listener(int how, int lfd, int idle1, int idle2) {
    if (how == 0 || how == 1) {
        struct pollfd p[3] = {{idle1, POLLIN, 0}, {lfd, POLLIN, 0}, {idle2, POLLIN, 0}};
        int r;
        if (how == 0) {
            r = poll(p, 3, 2000);
        } else {
            struct timespec ts = {2, 0};
            r = ppoll(p, 3, &ts, NULL);
        }
        return r >= 1 && (p[1].revents & POLLIN);
    }
    int ep = epoll_create1(EPOLL_CLOEXEC);
    int fds[3] = {idle1, lfd, idle2};
    for (int i = 0; i < 3; i++) {
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = fds[i]};
        epoll_ctl(ep, EPOLL_CTL_ADD, fds[i], &ev);
    }
    struct epoll_event out[3];
    int r = epoll_wait(ep, out, 3, 2000);
    close(ep);
    for (int i = 0; i < r; i++)
        if (out[i].data.fd == lfd)
            return 1;
    return 0;
}

// Match the inode returned by fstat, including inode zero for a queued child.
// Linux prints abstract NULs as '@', retaining the rest of the name verbatim.
static int find_proc_row(FILE *f, unsigned long inode, unsigned kind, unsigned flags,
                         unsigned state, const char *name) {
    char *line = NULL;
    size_t cap = 0;
    int found = -1;
    if (getline(&line, &cap, f) > 0 &&
        strcmp(line, "Num       RefCount Protocol Flags    Type St Inode Path\n") == 0) {
        found = 0;
        while (getline(&line, &cap, f) > 0) {
            unsigned refs, protocol, fl, type, st;
            unsigned long ino;
            int off = 0;
            if (sscanf(line, "%*[^:]: %x %x %x %x %x %lu%n",
                       &refs, &protocol, &fl, &type, &st, &ino, &off) != 6)
                continue;
            char *path = line + off;
            if (*path == ' ') path++;
            path[strcspn(path, "\n")] = 0;
            if (ino == inode && protocol == 0 && fl == flags && type == kind &&
                st == state && strcmp(path, name) == 0) {
                found = 1;
                break;
            }
        }
        if (ferror(f)) found = -1;
    }
    free(line);
    return found;
}

static int has_proc_row(const char *table, unsigned long inode, unsigned kind,
                        unsigned flags, unsigned state, const char *name) {
    FILE *f = fopen(table, "r");
    if (!f) return -1;
    int found = find_proc_row(f, inode, kind, flags, state, name);
    fclose(f);
    return found;
}

// A proc fd opened before unshare keeps its namespace even on its first read.
// /proc/<parent>/net selects the parent; /proc/net and thread-self select us.
static int check_private_net(int parent, unsigned long inode) {
    FILE *before = fopen("/proc/net/unix", "r");
    if (!before || unshare(CLONE_NEWNET) != 0) return 0;
    char table[64];
    snprintf(table, sizeof table, "/proc/%d/net/unix", parent);
    int ok = find_proc_row(before, inode, SOCK_DGRAM, 0, 1, "") == 1 &&
             has_proc_row(table, inode, SOCK_DGRAM, 0, 1, "") == 1 &&
             has_proc_row("/proc/net/unix", inode, SOCK_DGRAM, 0, 1, "") == 0;
    fclose(before);
    int pair[2];
    if (!ok || socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 0;
    struct stat st;
    ok = fstat(pair[0], &st) == 0 &&
         has_proc_row("/proc/thread-self/net/unix", st.st_ino, SOCK_SEQPACKET, 0, 3, "") == 1 &&
         has_proc_row(table, st.st_ino, SOCK_SEQPACKET, 0, 3, "") == 0;
    close(pair[0]);
    close(pair[1]);
    return ok;
}

static int check_proc_netns(void) {
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0) return 0;
    pid_t parent = getpid(), child = fork();
    if (child == 0) _exit(check_private_net(parent, st.st_ino) ? 0 : 1);
    int status;
    int ok = child > 0 && waitpid(child, &status, 0) == child &&
             WIFEXITED(status) && WEXITSTATUS(status) == 0;
    close(fd);
    puts(ok ? "proc-netns-ok" : "proc-netns-failed");
    return ok;
}

// unix_dgram_connect establishes the destination too, without giving it a
// default send address. AF_UNSPEC clears both states on disconnection.
static int check_proc_dgram(void) {
    struct sockaddr_un addr;
    struct sockaddr disconnect = {.sa_family = AF_UNSPEC};
    char name[48], printed[52];
    snprintf(name, sizeof name, "narf-dgram-%d", (int)getpid());
    int len = make_addr(1, name, &addr);
    snprintf(printed, sizeof printed, "@%s", name);
    int dest = socket(AF_UNIX, SOCK_DGRAM, 0);
    int src = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct stat st, sender;
    int ok = dest >= 0 && src >= 0 && fstat(dest, &st) == 0 && fstat(src, &sender) == 0 &&
             bind(dest, (void *)&addr, len) == 0 &&
             has_proc_row("/proc/net/unix", st.st_ino, SOCK_DGRAM, 0, 1, printed) == 1 &&
             connect(src, (void *)&addr, len) == 0 &&
             has_proc_row("/proc/net/unix", sender.st_ino, SOCK_DGRAM, 0, 3, "") == 1 &&
             has_proc_row("/proc/net/unix", st.st_ino, SOCK_DGRAM, 0, 3, printed) == 1 &&
             connect(src, &disconnect, sizeof disconnect.sa_family) == 0 &&
             has_proc_row("/proc/net/unix", sender.st_ino, SOCK_DGRAM, 0, 1, "") == 1 &&
             has_proc_row("/proc/net/unix", st.st_ino, SOCK_DGRAM, 0, 1, printed) == 1;
    if (dest >= 0) close(dest);
    if (src >= 0) close(src);
    if (!ok) puts("proc-unix-dgram-failed");
    return ok;
}

static int check_proc_unix(void) {
    struct sockaddr_un addr;
    char name[48], printed[52];
    snprintf(name, sizeof name, "narf-proc-%d", (int)getpid());
    int len = make_addr(1, name, &addr);
    addr.sun_path[1 + strlen(name)] = 0;
    addr.sun_path[2 + strlen(name)] = (char)0xff;
    len += 2;
    snprintf(printed, sizeof printed, "@%s@%c", name, 0xff);
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    int accepted = -1, ok = 0;
    struct stat lst, cli, srv;
    if (listener < 0 || client < 0 || bind(listener, (void *)&addr, len) ||
        listen(listener, 1) || fstat(listener, &lst) || fstat(client, &cli) ||
        has_proc_row("/proc/self/net/unix", lst.st_ino, SOCK_STREAM, 0x10000, 1, printed) != 1 ||
        connect(client, (void *)&addr, len) ||
        has_proc_row("/proc/net/unix", cli.st_ino, SOCK_STREAM, 0, 3, "") != 1 ||
        has_proc_row("/proc/net/unix", 0, SOCK_STREAM, 0, 2, printed) != 1) goto out;
    accepted = accept(listener, NULL, NULL);
    if (accepted < 0 || fstat(accepted, &srv) ||
        has_proc_row("/proc/thread-self/net/unix", srv.st_ino, SOCK_STREAM, 0, 3, printed) != 1) goto out;
    close(accepted);
    accepted = -1;
    if (has_proc_row("/proc/net/unix", srv.st_ino, SOCK_STREAM, 0, 3, printed) != 0) goto out;
    ok = 1;
out:
    if (accepted >= 0) close(accepted);
    if (client >= 0) close(client);
    if (listener >= 0) close(listener);
    puts(ok ? "proc-unix-ok" : "proc-unix-failed");
    return ok;
}

int main(int argc, char **argv) {
    if (!check_proc_dgram() || !check_proc_unix()) return 1;
    if (argc == 2 && strcmp(argv[1], "--proc-netns") == 0) return !check_proc_netns();
    if (argc == 2 && strcmp(argv[1], "--proc-only") == 0) return 0;
    static const char *how_name[] = {"poll", "ppoll", "epoll"};
    int failed = 0;
    char path[64];
    snprintf(path, sizeof path, "/tmp/ulw-%d.sock", (int)getpid());
    int idle[2], idle2[2];
    if (pipe(idle) != 0 || pipe(idle2) != 0)
        return 1;

    for (int abstract = 0; abstract < 2; abstract++)
        for (int how = 0; how < 3; how++)
            for (int with_data = 0; with_data < 2; with_data++) {
                struct sockaddr_un a;
                char name[128];
                snprintf(name, sizeof name, "%s%s", abstract ? "ulw-abs-" : "", path);
                if (!abstract)
                    unlink(path);
                int alen = make_addr(abstract, abstract ? name : path, &a);
                int l = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
                if (l < 0 || bind(l, (struct sockaddr *)&a, alen) != 0 || listen(l, 16) != 0) {
                    printf("unix-listen-wake-fail: setup errno=%d\n", errno);
                    return 1;
                }
                for (int r = 0; r < ROUNDS; r++) {
                    int delay_us = (r % 2) ? 20000 : 0;
                    pid_t c = fork();
                    if (c == 0) {
                        if (delay_us)
                            usleep(delay_us);
                        int s = socket(AF_UNIX, SOCK_STREAM, 0);
                        if (connect(s, (struct sockaddr *)&a, alen) != 0)
                            _exit(2);
                        if (with_data)
                            (void)send(s, "x", 1, MSG_NOSIGNAL);
                        usleep(300000); // keep the connection open while polled
                        _exit(0);
                    }
                    int ok = wait_listener(how, l, idle[0], idle2[0]);
                    int s = accept4(l, NULL, NULL, SOCK_CLOEXEC);
                    if (s >= 0)
                        close(s);
                    int st = 0;
                    waitpid(c, &st, 0);
                    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
                        printf("unix-listen-wake-fail: case=%s/%s/%s round=%d (client connect failed, status %#x)\n",
                               abstract ? "abstract" : "path", how_name[how],
                               with_data ? "connect+write" : "connect-only", r, st);
                        failed = 1;
                        break;
                    }
                    if (!ok) {
                        printf("unix-listen-wake-fail: case=%s/%s/%s round=%d (listener never became readable)\n",
                               abstract ? "abstract" : "path", how_name[how],
                               with_data ? "connect+write" : "connect-only", r);
                        failed = 1;
                        break;
                    }
                }
                close(l);
                if (!abstract)
                    unlink(path);
            }
    if (failed)
        return 1;
    printf("unix-listen-wake-ok\n");
    return 0;
}
