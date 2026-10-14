// A kernel write into a read-only, not-yet-resident file mapping is EFAULT.
//
// read(2) into a PROT_READ MAP_PRIVATE file mapping: Linux's copy_to_user
// takes the fault, `handle_mm_fault` reads the page in (sleeping on the I/O),
// the retry faults again on the write-protected PTE, and the exception table
// turns that into a short copy -> -EFAULT. Nothing about the sleep in the
// middle is special.
//
// NARF kept the uaccess recovery in a per-CPU slot armed by the copy. The
// first fault parked the task on the file read, the task resumed on another
// CPU, and the second fault found that CPU's slot empty: a kernel #PF panic
// with SMAP's AC still set. A sandboxed Chromium renderer reached it through
// prlimit64 writing into a read-only mapping.
//
// Every page is touched once and only by the kernel, so each one starts
// non-resident in this address space (and, for a file not read since boot,
// outside the page cache too).
//
// Success token "uaccessfile-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char *pick(void) {
    static const char *c[] = {"/usr/lib/chromium/chromium", "/usr/lib/libc.so.6",
                              "/lib/libc.so", "/proc/self/exe", 0};
    for (int i = 0; c[i]; i++)
        if (access(c[i], R_OK) == 0) return c[i];
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IONBF, 0);
    const char *path = argc > 1 ? argv[1] : pick();
    int fd = path ? open(path, O_RDONLY) : -1;
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || st.st_size < 4096) {
        printf("uaccessfile-fail: no readable file (errno=%d)\n", errno);
        return 1;
    }
    size_t pages = st.st_size / 4096;
    char *m = mmap(0, pages * 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED) {
        printf("uaccessfile-fail: mmap errno=%d\n", errno);
        return 1;
    }
    int p[2];
    if (pipe(p) != 0) return 1;
    size_t step = pages > 4096 ? pages / 4096 : 1;
    int bad = 0, n = 0;
    for (size_t i = 0; i < pages && n < 4096; i += step, n++) {
        char *a = m + i * 4096;
        if (write(p[1], "0123456789abcdef", 16) != 16) return 1;
        errno = 0;
        long r = read(p[0], a, 16);
        if (r != -1 || errno != EFAULT) {
            if (bad++ < 5) printf("uaccessfile-fail: read into %s page %zu = %ld errno=%d\n", path, i, r, errno);
        }
        char sink[16];
        if (r == -1) read(p[0], sink, 16);  // the bytes stayed in the pipe
        // The same through a syscall whose output is a small struct.
        errno = 0;
        r = syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, 0, a + 64);
        if (r != -1 || errno != EFAULT) {
            if (bad++ < 5) printf("uaccessfile-fail: prlimit64 into page %zu = %ld errno=%d\n", i, r, errno);
        }
    }
    if (bad) {
        printf("uaccessfile-fail: %d of %d\n", bad, n * 2);
        return 1;
    }
    printf("uaccessfile-ok pages=%d file=%s\n", n, path);
    return 0;
}
