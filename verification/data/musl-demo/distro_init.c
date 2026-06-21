/* Boot a real Linux distro userland on the NARF kernel.
 *
 * NARF mounts a real Alpine Linux 3.21 rootfs (ext2 on virtio-blk) at /mnt.
 * This launcher chroot()s into it and execve()s Alpine's OWN busybox — an
 * unmodified distro binary, dynamically linked against Alpine's OWN musl
 * (/lib/ld-musl-x86_64.so.1 inside the chroot). If the kernel resolves the
 * binary AND its PT_INTERP under the chroot root and runs it, a real distro's
 * userland is executing on NARF — the container-runtime model.
 *
 * Prints diagnostics for each step, then (on success) hands off to Alpine's
 * busybox which prints `alpine-busybox-ran` — unambiguous proof that an
 * unmodified Alpine binary executed on the NARF kernel.
 */
#define _GNU_SOURCE 1
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

extern char **environ;

int main(void) {
    if (chroot("/mnt") != 0) { printf("chroot-fail errno=%d\n", errno); return 1; }
    if (chdir("/") != 0) { printf("chdir-fail errno=%d\n", errno); return 1; }

    /* Confirm the chroot re-rooted path lookups: read Alpine's release file
     * via the now-relative "/etc/alpine-release". */
    int f = open("/etc/alpine-release", O_RDONLY);
    if (f < 0) { printf("open-release-fail errno=%d\n", errno); return 1; }
    char b[16]; int n = (int)read(f, b, 15); close(f);
    if (n <= 0) { printf("read-release-fail\n"); return 1; }
    b[n] = 0;
    printf("chroot-ok release=%s", b); /* file already ends in \n */

    struct stat st;
    int has_bb = (stat("/bin/busybox", &st) == 0);
    int has_interp = (stat("/lib/ld-musl-x86_64.so.1", &st) == 0);
    printf("busybox=%d interp=%d\n", has_bb, has_interp);
    fflush(stdout);

    /* busybox's ash PATH-searches for applets (cat, uname, ...) which live
     * as symlinks in /bin — give it a PATH that includes them. */
    setenv("PATH", "/bin:/usr/bin:/sbin:/usr/sbin", 1);

    /* Hand off to the real Alpine busybox running a shell session that
     * exercises several applets — proving a real distro userland works. */
    char *argv[] = {
        (char *)"busybox", (char *)"sh", (char *)"-c",
        (char *)"echo '=== Alpine on NARF ==='; "
                "cat /etc/os-release; "
                "echo -n 'uname: '; uname -sm; "
                "echo alpine-shell-ran",
        NULL
    };
    execve("/bin/busybox", argv, environ);
    printf("execve-fail errno=%d\n", errno);
    return 1;
}
