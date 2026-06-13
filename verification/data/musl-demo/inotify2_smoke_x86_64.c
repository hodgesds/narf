// inotify event-delivery smoke. Unlike inotify_smoke (which only checks
// watch-descriptor bookkeeping), this verifies NARF now generates real
// filesystem-change events: watch a directory, then create / write /
// delete a file inside it and read back the IN_CREATE, IN_MODIFY and
// IN_DELETE events (each naming the file). Success token "inotify2-ok".
//
// Build: see REGEN_inotify2_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/inotify.h>

static void w(const char *m) { write(1, m, strlen(m)); }

#define NAME "ino2_target"
#define DIR "/dev/shm"
#define PATH DIR "/" NAME

int main(void) {
    int infd = inotify_init1(IN_NONBLOCK);
    if (infd < 0) { w("inotify2-fail: init\n"); return 1; }
    int wd = inotify_add_watch(infd, DIR, IN_CREATE | IN_MODIFY | IN_DELETE);
    if (wd < 0) { w("inotify2-fail: add\n"); return 1; }

    // Generate the three events.
    int fd = open(PATH, O_CREAT | O_RDWR, 0600);   // IN_CREATE
    if (fd < 0) { w("inotify2-fail: open\n"); return 1; }
    if (write(fd, "data", 4) != 4) { w("inotify2-fail: write\n"); return 1; }  // IN_MODIFY
    close(fd);
    if (unlink(PATH) != 0) { w("inotify2-fail: unlink\n"); return 1; }          // IN_DELETE

    // Read and walk the event stream.
    char buf[1024];
    ssize_t n = read(infd, buf, sizeof buf);
    if (n <= 0) { w("inotify2-fail: read\n"); return 1; }

    uint32_t seen = 0;
    char *p = buf;
    while (p + sizeof(struct inotify_event) <= buf + n) {
        struct inotify_event *e = (struct inotify_event *)p;
        // Every event must name our file (watch is on the parent dir).
        if (e->len > 0 && strcmp(e->name, NAME) != 0) {
            w("inotify2-fail: name\n"); return 1;
        }
        seen |= e->mask & (IN_CREATE | IN_MODIFY | IN_DELETE);
        p += sizeof(struct inotify_event) + e->len;
    }
    close(infd);

    if ((seen & IN_CREATE) == 0) { w("inotify2-fail: no-create\n"); return 1; }
    if ((seen & IN_MODIFY) == 0) { w("inotify2-fail: no-modify\n"); return 1; }
    if ((seen & IN_DELETE) == 0) { w("inotify2-fail: no-delete\n"); return 1; }

    w("inotify2-ok\n");
    return 0;
}
