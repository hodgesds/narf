// Process-introspection smoke: pidfd_getfd + kcmp, issued raw via
// syscall(2) (musl gates/omits these wrappers). Open a pidfd on ourselves,
// clone a pipe read-end out of our own process through it, confirm the
// clone reads the bytes written to the pipe, then check kcmp reports that
// a process shares its VM and file table with itself. Success token
// "introspect-ok".
//
// Build: see REGEN_introspect_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>

static void w(const char *m) { write(1, m, strlen(m)); }

#define KCMP_VM 1
#define KCMP_FILES 2

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) { w("introspect-fail: pipe\n"); return 1; }

    long pidfd = syscall(SYS_pidfd_open, (long)getpid(), 0L);
    if (pidfd < 0) { w("introspect-fail: pidfd_open\n"); return 1; }

    long clone_fd = syscall(SYS_pidfd_getfd, pidfd, (long)fds[0], 0L);
    if (clone_fd < 0) { w("introspect-fail: pidfd_getfd\n"); return 1; }

    if (write(fds[1], "Z", 1) != 1) { w("introspect-fail: write\n"); return 1; }
    char c = 0;
    if (read((int)clone_fd, &c, 1) != 1 || c != 'Z') {
        w("introspect-fail: clone-read\n"); return 1;
    }

    // A process shares VM and files with itself.
    if (syscall(SYS_kcmp, (long)getpid(), (long)getpid(), KCMP_VM, 0L, 0L) != 0) {
        w("introspect-fail: kcmp-vm\n"); return 1;
    }
    if (syscall(SYS_kcmp, (long)getpid(), (long)getpid(), KCMP_FILES, 0L, 0L) != 0) {
        w("introspect-fail: kcmp-files\n"); return 1;
    }
    // An out-of-range comparison type is rejected.
    if (syscall(SYS_kcmp, (long)getpid(), (long)getpid(), 99L, 0L, 0L) != -1) {
        w("introspect-fail: kcmp-badtype\n"); return 1;
    }

    w("introspect-ok\n");
    return 0;
}
