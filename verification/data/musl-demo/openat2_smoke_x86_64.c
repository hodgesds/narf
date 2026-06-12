// openat2(2) smoke. Create a file with open(), then re-open it via
// openat2 with an open_how struct and read the contents back. open_how
// is defined locally so the test doesn't depend on <linux/openat2.h>.
// Success token "openat2-ok".
//
// Build: see REGEN_openat2_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

struct narf_open_how {
    unsigned long long flags;
    unsigned long long mode;
    unsigned long long resolve;
};

#define PATH "/dev/shm/oat2_test"

int main(void) {
    const char *data = "openat2-data";
    size_t n = strlen(data);

    int fd = open(PATH, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        w("openat2-fail: create\n");
        return 1;
    }
    if (write(fd, data, n) != (ssize_t)n) {
        w("openat2-fail: write\n");
        return 1;
    }
    close(fd);

    struct narf_open_how how;
    memset(&how, 0, sizeof how);
    how.flags = O_RDONLY;
    long ofd = syscall(SYS_openat2, AT_FDCWD, PATH, &how, sizeof how);
    if (ofd < 0) {
        w("openat2-fail: openat2\n");
        return 1;
    }
    char buf[32] = {0};
    ssize_t r = read((int)ofd, buf, sizeof buf);
    if (r == (ssize_t)n && memcmp(buf, data, n) == 0) {
        w("openat2-ok\n");
    } else {
        w("openat2-fail: verify\n");
    }
    close((int)ofd);
    return 0;
}
