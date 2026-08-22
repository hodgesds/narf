/* Generic Alpine-chroot launcher: prepare writable /tmp and /dev/shm mounts,
 * chroot into the mounted rootfs (/mnt, with /dev bind-mounted), and run
 * /probe.sh via the distro's busybox. Lets us iterate on "run real Linux
 * software, see what breaks" by editing /probe.sh in the rootfs image — no
 * kernel rebuild. The script ends by printing PROBE-DONE. */
#define _GNU_SOURCE 1
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mount.h>
extern char **environ;

static int mount_scratch_tmpfs(const char *target, const char *options) {
    if (mount("tmpfs", target, "tmpfs", MS_NOSUID | MS_NODEV, options) == 0)
        return 0;
    printf("tmpfs-mount-fail target=%s errno=%d\n", target, errno);
    return -1;
}

int main(int argc, char **argv) {
    /* A plain bind of /dev intentionally does not carry nested mounts, just as
     * Linux mount --bind differs from --rbind.  Build the two writable runtime
     * mounts explicitly before entering the distro root: musl implements
     * shm_open() as open("/dev/shm/<name>", ...), and stress-ng must not reuse
     * stale scratch files left in the persistent ext image. */
    if (mount_scratch_tmpfs("/mnt/tmp", "mode=1777") != 0) return 1;
    if (mount_scratch_tmpfs("/mnt/dev/shm", "mode=1777") != 0) return 1;
    if (chroot("/mnt") != 0) { printf("chroot-fail errno=%d\n", errno); return 1; }
    if (chdir("/tmp") != 0) { printf("chdir-fail errno=%d\n", errno); return 1; }
    setenv("XDG_RUNTIME_DIR", "/tmp", 1);
    setenv("PATH", "/bin:/usr/bin:/sbin:/usr/sbin:/usr/libexec/libinput", 1);
    setenv("LD_LIBRARY_PATH", "/usr/lib:/lib", 1);
    if (argc > 1) {
        execve(argv[1], &argv[1], environ);
        printf("exec-fail path=%s errno=%d\n", argv[1], errno);
        return 1;
    }
    char *default_argv[] = { (char *)"busybox", (char *)"sh", (char *)"/probe.sh", NULL };
    execve("/bin/busybox", default_argv, environ);
    /* Rootfs without busybox (e.g. a stock Debian bundle): run the probe
     * through the distro's own /bin/sh. Never fake a /bin/busybox inside
     * the rootfs to satisfy the exec above — a shim that re-execs the
     * probe script turns every later `busybox APPLET` invocation into a
     * script re-run (looks like execve corruption / a fork bomb). */
    char *sh_argv[] = { (char *)"sh", (char *)"/probe.sh", NULL };
    execve("/bin/sh", sh_argv, environ);
    printf("exec-fail errno=%d\n", errno);
    return 1;
}
