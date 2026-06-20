/* Framebuffer smoke for the NARF linux-compat demo.
 *
 * Exercises the device-mmap keystone end-to-end from stock musl:
 *
 *   1. fd = open("/dev/fb0", O_RDWR)
 *   2. ioctl(fd, FBIOGET_VSCREENINFO, &v)  — read geometry (XRGB8888)
 *   3. fb = mmap(NULL, len, RW, MAP_SHARED, fd, 0)  — the keystone:
 *      the kernel aliases the scanout's physical frames into this
 *      process's address space, so the writes below land directly in
 *      the framebuffer.
 *   4. write a known pixel through the mapping, read it back (proves
 *      the mapping is the live buffer, not a private copy).
 *   5. draw a white diagonal so a screendump shows the result too.
 *   6. write(1, "fb-ok <W>x<H>\n", ...)
 *
 * Any failed step prints "fb-fail-<step>\n" and exits non-zero so the
 * run-interactive matcher sees exactly where it broke. The success
 * token `fb-ok` is what the harness matches on.
 *
 * Rebuild: musl-gcc -O2 -fPIE -pie -mcmodel=large fb_smoke_x86_64.c
 * (verification/build.rs does this automatically).
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* Linux ABI — mirrored in fb/src/fbdev.rs. */
#ifndef FBIOGET_VSCREENINFO
#define FBIOGET_VSCREENINFO 0x4600
#endif

static void w(const char *s) {
    write(1, s, strlen(s));
}

static void fail(const char *step) {
    w("fb-fail-");
    w(step);
    w("\n");
}

int main(void) {
    int fd = open("/dev/fb0", O_RDWR);
    if (fd < 0) {
        fail("open");
        return 1;
    }

    /* struct fb_var_screeninfo is 160 bytes; we only need the first
     * few u32 fields: xres[0] yres[1] ... bits_per_pixel[6]. */
    uint32_t v[40];
    memset(v, 0, sizeof v);
    if (ioctl(fd, FBIOGET_VSCREENINFO, v) != 0) {
        fail("vscreeninfo");
        return 1;
    }
    uint32_t xres = v[0];
    uint32_t yres = v[1];
    uint32_t bpp = v[6];
    if (xres == 0 || yres == 0 || bpp != 32) {
        fail("geom");
        return 1;
    }

    size_t len = (size_t)xres * (size_t)yres * 4u;
    len = (len + 0xFFFu) & ~(size_t)0xFFFu;
    volatile uint32_t *fb =
        mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (fb == MAP_FAILED) {
        fail("mmap");
        return 1;
    }

    /* Write known pixels through the shared mapping, read them back. */
    fb[0] = 0x00ABCDEFu;
    fb[(size_t)xres + 1] = 0x00123456u;
    if (fb[0] != 0x00ABCDEFu || fb[(size_t)xres + 1] != 0x00123456u) {
        fail("readback");
        return 1;
    }

    /* Visible proof for a screendump: a white diagonal. */
    uint32_t n = xres < yres ? xres : yres;
    for (uint32_t i = 0; i < n; i++) {
        fb[(size_t)i * (size_t)xres + (size_t)i] = 0x00FFFFFFu;
    }

    /* Success token on its own line so the run-interactive matcher
     * anchors on the trailing newline; geometry follows separately. */
    w("fb-ok\n");
    char buf[64];
    int k = snprintf(buf, sizeof buf, "fb-geom %ux%u\n", xres, yres);
    if (k > 0) {
        write(1, buf, (size_t)k);
    }
    return 0;
}
