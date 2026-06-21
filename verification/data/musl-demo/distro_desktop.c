/* Run the Wayland desktop INSIDE the booted Alpine distro on NARF.
 *
 * distro_init proved a real Alpine userland runs on NARF. This goes further:
 * it runs the GUI stack from *inside* that distro. The kernel bind-mounts
 * NARF's /dev into the Alpine rootfs (/mnt/dev) at boot, so device files are
 * reachable from within the chroot. This launcher chroot()s into Alpine and
 * execs /bin/wl_app (the compositor + the unmodified weston-simple-shm
 * client, both placed in the Alpine image), which open /dev/fb0 + /dev/dri,
 * map an xdg_toplevel, and present a frame.
 *
 * On success /bin/wl_app prints `app-ok WxH win=250x250` — a Wayland desktop
 * compositing a real GUI client, running entirely within the Alpine distro
 * userland on the NARF kernel.
 */
#define _GNU_SOURCE 1
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

extern char **environ;

int main(void) {
    if (chroot("/mnt") != 0) { printf("ddesk-chroot-fail errno=%d\n", errno); return 1; }
    if (chdir("/") != 0) { printf("ddesk-chdir-fail errno=%d\n", errno); return 1; }
    setenv("XDG_RUNTIME_DIR", "/tmp", 1);
    setenv("PATH", "/bin:/usr/bin:/usr/local/bin", 1);
    setenv("WAYLAND_DEBUG", "0", 1);
    /* /bin/wl_app is our compositor; it fork+execve's /bin/simple_shm. Both
     * live in the Alpine image and run against Alpine's own musl. */
    char *argv[] = { (char *)"/bin/wl_app", NULL };
    execve("/bin/wl_app", argv, environ);
    printf("ddesk-exec-fail errno=%d\n", errno);
    return 1;
}
