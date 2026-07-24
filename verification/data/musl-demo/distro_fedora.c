/* Boot a real Fedora 43 (glibc) userland — and its KDE Plasma desktop — on
 * the NARF kernel.
 *
 * Counterpart to distro_init/distro_kde (Alpine/musl). NARF mounts the Fedora
 * ext2 rootfs at /mnt; this launcher chroot()s into it and execve()s Fedora's
 * OWN /bin/bash running /narf-start.sh. Everything past the chroot is stock
 * Fedora: glibc's ld-linux-x86-64.so.2 resolves every DSO under the new root.
 *
 * All the interesting logic lives in the in-image /narf-start.sh so it can be
 * iterated with `debugfs -w` without rebuilding the kernel.
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
    if (chroot("/mnt") != 0) { printf("dfed-chroot-fail errno=%d\n", errno); return 1; }
    if (chdir("/") != 0) { printf("dfed-chdir-fail errno=%d\n", errno); return 1; }

    /* Prove the re-root took: read Fedora's own release file. */
    int f = open("/etc/fedora-release", O_RDONLY);
    if (f < 0) { printf("dfed-open-release-fail errno=%d\n", errno); return 1; }
    char b[64];
    int n = (int)read(f, b, sizeof(b) - 1);
    close(f);
    if (n <= 0) { printf("dfed-read-release-fail\n"); return 1; }
    b[n] = 0;
    printf("dfed-chroot-ok release=%s", b); /* file ends in \n */

    /* glibc's dynamic loader + the shell must both be present, else the
     * execve below fails with a bare ENOENT that says nothing about which
     * of the two is missing. */
    struct stat st;
    int has_sh = (stat("/bin/bash", &st) == 0);
    int has_interp = (stat("/lib64/ld-linux-x86-64.so.2", &st) == 0);
    int has_start = (stat("/narf-start.sh", &st) == 0);
    printf("dfed-probe bash=%d interp=%d start=%d\n", has_sh, has_interp, has_start);
    fflush(stdout);

    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("HOME", "/root", 1);
    setenv("TERM", "linux", 1);

    char *argv[] = { (char *)"bash", (char *)"/narf-start.sh", NULL };
    execve("/bin/bash", argv, environ);
    printf("dfed-execve-fail errno=%d\n", errno);
    return 1;
}
