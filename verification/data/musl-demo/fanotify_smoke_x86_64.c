// fanotify smoke: real event delivery via NARF's fs_notify dispatch.
// Mark a file for FAN_OPEN|FAN_MODIFY|FAN_CLOSE_WRITE, then open/write/
// close it and read back struct fanotify_event_metadata records — each
// carrying an OPEN fd to the object, which we read to confirm it really
// points at our file. Issued raw (struct + constants defined locally) so
// it builds regardless of musl header age. Success token "fanotify-ok".
//
// Build: see REGEN_fanotify_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/syscall.h>

#ifndef SYS_fanotify_init
#define SYS_fanotify_init 300
#endif
#ifndef SYS_fanotify_mark
#define SYS_fanotify_mark 301
#endif

#define FAN_NONBLOCK 0x00000002
#define FAN_CLASS_NOTIF 0x00000000
#define FAN_MARK_ADD 0x00000001
#define FAN_MODIFY 0x00000002
#define FAN_CLOSE_WRITE 0x00000008
#define FAN_OPEN 0x00000020
#define FANOTIFY_METADATA_VERSION 3
#define ATFD (-100) /* AT_FDCWD */

struct fan_meta {
    uint32_t event_len;
    uint8_t vers;
    uint8_t reserved;
    uint16_t metadata_len;
    uint64_t mask;
    int32_t fd;
    int32_t pid;
};

static void w(const char *m) { write(1, m, strlen(m)); }

#define PATH "/dev/shm/fan_target"
#define PAYLOAD "fanotify-payload"

int main(void) {
    long g = syscall(SYS_fanotify_init, FAN_CLASS_NOTIF | FAN_NONBLOCK, 0L /*O_RDONLY*/);
    if (g < 0) { w("fanotify-fail: init\n"); return 1; }

    // Create the target empty, before marking (so creation isn't reported).
    int t = open(PATH, O_CREAT | O_RDWR, 0600);
    if (t < 0) { w("fanotify-fail: create\n"); return 1; }
    close(t);

    if (syscall(SYS_fanotify_mark, g, (long)FAN_MARK_ADD,
                (long)(FAN_OPEN | FAN_MODIFY | FAN_CLOSE_WRITE), (long)ATFD, PATH) != 0) {
        w("fanotify-fail: mark\n"); return 1;
    }

    // Generate the three marked events.
    int fd = open(PATH, O_RDWR);                 // FAN_OPEN
    if (fd < 0) { w("fanotify-fail: open\n"); return 1; }
    if (write(fd, PAYLOAD, strlen(PAYLOAD)) != (ssize_t)strlen(PAYLOAD)) { // FAN_MODIFY
        w("fanotify-fail: write\n"); return 1;
    }
    close(fd);                                   // FAN_CLOSE_WRITE

    // Read and walk the metadata stream.
    char buf[512];
    ssize_t n = read((int)g, buf, sizeof buf);
    if (n <= 0) { w("fanotify-fail: read\n"); return 1; }

    uint64_t seen = 0;
    int checked_content = 0;
    char *p = buf;
    while (p + (long)sizeof(struct fan_meta) <= buf + n) {
        struct fan_meta *e = (struct fan_meta *)p;
        if (e->vers != FANOTIFY_METADATA_VERSION) { w("fanotify-fail: vers\n"); return 1; }
        if (e->metadata_len < sizeof(struct fan_meta)) { w("fanotify-fail: mlen\n"); return 1; }
        seen |= e->mask;
        if (e->fd >= 0) {
            // The delivered fd must open our file: read it back.
            char rb[64];
            ssize_t rn = pread(e->fd, rb, sizeof rb, 0);
            if (rn >= (ssize_t)strlen(PAYLOAD) && memcmp(rb, PAYLOAD, strlen(PAYLOAD)) == 0) {
                checked_content = 1;
            }
            close(e->fd);
        }
        p += e->event_len ? e->event_len : (long)sizeof(struct fan_meta);
    }
    close((int)g);
    unlink(PATH);

    if ((seen & FAN_OPEN) == 0) { w("fanotify-fail: no-open\n"); return 1; }
    if ((seen & FAN_MODIFY) == 0) { w("fanotify-fail: no-modify\n"); return 1; }
    if ((seen & FAN_CLOSE_WRITE) == 0) { w("fanotify-fail: no-close\n"); return 1; }
    if (!checked_content) { w("fanotify-fail: bad-fd\n"); return 1; }

    w("fanotify-ok\n");
    return 0;
}
