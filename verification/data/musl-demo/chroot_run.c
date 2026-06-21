/* Generic Alpine-chroot launcher: chroot into the mounted rootfs (/mnt, with
 * /dev bind-mounted + a writable /tmp by the mnt-dev-bind boot step) and run
 * /probe.sh via the distro's busybox. Lets us iterate on "run real Linux
 * software, see what breaks" by editing /probe.sh in the rootfs image — no
 * kernel rebuild. The script ends by printing PROBE-DONE. */
#define _GNU_SOURCE 1
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
extern char **environ;
int main(void) {
    if (chroot("/mnt") != 0) { printf("chroot-fail errno=%d\n", errno); return 1; }
    if (chdir("/") != 0) { printf("chdir-fail errno=%d\n", errno); return 1; }
    setenv("XDG_RUNTIME_DIR", "/tmp", 1);
    setenv("PATH", "/bin:/usr/bin:/sbin:/usr/sbin:/usr/libexec/libinput", 1);
    setenv("LD_LIBRARY_PATH", "/usr/lib:/lib", 1);
    char *argv[] = { (char *)"busybox", (char *)"sh", (char *)"/probe.sh", NULL };
    execve("/bin/busybox", argv, environ);
    printf("exec-fail errno=%d\n", errno);
    return 1;
}
