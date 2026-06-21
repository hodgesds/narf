/* DRM/KMS dumb-buffer modeset smoke for NARF.
 *
 * Exercises the DRM_IOCTL_MODE_* path end-to-end from stock musl:
 *
 *   1. fd = open("/dev/dri/card0", O_RDWR)
 *   2. DRM_IOCTL_GET_CAP(DUMB_BUFFER) == 1
 *   3. DRM_IOCTL_MODE_GETRESOURCES — discover crtc_id + connector_id
 *   4. DRM_IOCTL_MODE_CREATE_DUMB(W, H, 32bpp) — allocate dumb buffer
 *   5. DRM_IOCTL_MODE_MAP_DUMB — get fake mmap offset
 *   6. mmap(NULL, size, RW, MAP_SHARED, fd, offset) — map the buffer
 *   7. draw a test pattern
 *   8. DRM_IOCTL_MODE_ADDFB2 — register framebuffer
 *   9. DRM_IOCTL_MODE_SETCRTC — set the mode (blits to scanout)
 *  10. print "drm-ok\n" + "drm-geom WxH\n"
 *
 * Any failed step prints "drm-fail-<step>\n" and exits non-zero so the
 * run-interactive matcher sees exactly where it broke.
 *
 * Rebuild: musl-gcc -O2 -fPIE -pie -mcmodel=large drm_smoke_x86_64.c
 * (verification/build.rs does this automatically).
 *
 * DRM ioctl numbers (x86_64 _IOWR encoding):
 *   GET_CAP         = 0xC010640C
 *   MODE_GETRESOURCES = 0xC040640x40 = 0xC04064A0
 *   MODE_GETCONNECTOR = 0xC05064A7
 *   MODE_CREATE_DUMB  = 0xC02064B2
 *   MODE_MAP_DUMB     = 0xC01064B3
 *   MODE_ADDFB2       = 0xC06864B8
 *   MODE_SETCRTC      = 0xC06864A2
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* ── DRM ioctl numbers (x86_64) ─────────────────────────────────────── */
#define DRM_IOCTL_GET_CAP           0xC010640CU
#define DRM_IOCTL_MODE_GETRESOURCES 0xC04064A0U
#define DRM_IOCTL_MODE_GETCONNECTOR 0xC05064A7U
#define DRM_IOCTL_MODE_CREATE_DUMB  0xC02064B2U
#define DRM_IOCTL_MODE_MAP_DUMB     0xC01064B3U
#define DRM_IOCTL_MODE_ADDFB2       0xC06864B8U
#define DRM_IOCTL_MODE_SETCRTC      0xC06864A2U

#define DRM_CAP_DUMB_BUFFER 0x1ULL

/* ── Wire structs (must match Linux UAPI exactly on x86_64) ─────────── */

struct drm_get_cap {
    uint64_t capability;
    uint64_t value;
};

struct drm_mode_card_res {
    uint64_t fb_id_ptr;
    uint64_t crtc_id_ptr;
    uint64_t connector_id_ptr;
    uint64_t encoder_id_ptr;
    uint32_t count_fbs;
    uint32_t count_crtcs;
    uint32_t count_connectors;
    uint32_t count_encoders;
    uint32_t min_width;
    uint32_t max_width;
    uint32_t min_height;
    uint32_t max_height;
};

struct drm_mode_create_dumb {
    uint32_t height;
    uint32_t width;
    uint32_t bpp;
    uint32_t flags;
    uint32_t handle;
    uint32_t pitch;
    uint64_t size;
};

struct drm_mode_map_dumb {
    uint32_t handle;
    uint32_t pad;
    uint64_t offset;
};

/* drm_mode_modeinfo: 68 bytes */
struct drm_mode_modeinfo {
    uint32_t clock;
    uint16_t hdisplay, hsync_start, hsync_end, htotal, hskew;
    uint16_t vdisplay, vsync_start, vsync_end, vtotal, vscan;
    uint32_t vrefresh;
    uint32_t flags;
    uint32_t type;
    char     name[32];
};

/* drm_mode_crtc: 104 bytes */
struct drm_mode_crtc {
    uint64_t set_connectors_ptr;
    uint32_t count_connectors;
    uint32_t crtc_id;
    uint32_t fb_id;
    uint32_t x, y;
    uint32_t gamma_size;
    uint32_t mode_valid;
    struct drm_mode_modeinfo mode;
};

/* drm_mode_fb_cmd2: 80 bytes */
struct drm_mode_fb_cmd2 {
    uint32_t fb_id;
    uint32_t width;
    uint32_t height;
    uint32_t pixel_format;
    uint32_t flags;
    uint32_t handles[4];
    uint32_t pitches[4];
    uint32_t offsets[4];
    uint64_t modifier[4];
};

/* ── Helpers ─────────────────────────────────────────────────────────── */

static void w(const char *s) {
    write(1, s, strlen(s));
}

static void fail(const char *step) {
    w("drm-fail-");
    w(step);
    w("\n");
}

int main(void) {
    int fd = open("/dev/dri/card0", O_RDWR);
    if (fd < 0) {
        fail("open");
        return 1;
    }

    /* Step 1: verify DUMB_BUFFER capability */
    struct drm_get_cap cap;
    memset(&cap, 0, sizeof cap);
    cap.capability = DRM_CAP_DUMB_BUFFER;
    if (ioctl(fd, DRM_IOCTL_GET_CAP, &cap) != 0 || cap.value != 1) {
        fail("getcap");
        return 1;
    }

    /* Step 2: GETRESOURCES — get first CRTC id */
    struct drm_mode_card_res res;
    memset(&res, 0, sizeof res);
    if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) != 0) {
        fail("getresources-count");
        return 1;
    }
    if (res.count_crtcs == 0) {
        fail("no-crtcs");
        return 1;
    }
    /* Second call: read IDs. */
    uint32_t crtc_ids[8];
    uint32_t conn_ids[8];
    memset(crtc_ids, 0, sizeof crtc_ids);
    memset(conn_ids, 0, sizeof conn_ids);
    res.crtc_id_ptr = (uint64_t)(uintptr_t)crtc_ids;
    res.count_crtcs = res.count_crtcs < 8 ? res.count_crtcs : 8;
    res.connector_id_ptr = (uint64_t)(uintptr_t)conn_ids;
    res.count_connectors = res.count_connectors < 8 ? res.count_connectors : 8;
    if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) != 0) {
        fail("getresources-ids");
        return 1;
    }
    uint32_t crtc_id   = crtc_ids[0];
    uint32_t conn_id   = conn_ids[0];
    if (crtc_id == 0) {
        fail("zero-crtc-id");
        return 1;
    }

    /* Step 3: pick a resolution from the connector modes.
     * Use a small fixed size that fits any display. */
    uint32_t W = 256, H = 256;

    /* Step 4: CREATE_DUMB */
    struct drm_mode_create_dumb cd;
    memset(&cd, 0, sizeof cd);
    cd.width  = W;
    cd.height = H;
    cd.bpp    = 32;
    if (ioctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &cd) != 0 || cd.handle == 0) {
        fail("create-dumb");
        return 1;
    }
    uint32_t gem_handle = cd.handle;
    uint32_t pitch      = cd.pitch;
    uint64_t buf_size   = cd.size;

    /* Step 5: MAP_DUMB */
    struct drm_mode_map_dumb md;
    memset(&md, 0, sizeof md);
    md.handle = gem_handle;
    if (ioctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &md) != 0 || md.offset == 0) {
        fail("map-dumb");
        return 1;
    }

    /* Step 6: mmap */
    volatile uint32_t *pixels = mmap(
        NULL, (size_t)buf_size,
        PROT_READ | PROT_WRITE, MAP_SHARED,
        fd, (off_t)md.offset);
    if (pixels == MAP_FAILED) {
        fail("mmap");
        return 1;
    }

    /* Step 7: draw a test pattern (alternating red/blue columns) */
    for (uint32_t y = 0; y < H; y++) {
        for (uint32_t x = 0; x < W; x++) {
            pixels[(size_t)y * (pitch / 4) + x] =
                (x & 1) ? 0x00FF0000u : 0x000000FFu;
        }
    }

    /* Step 8: ADDFB2 */
    struct drm_mode_fb_cmd2 fb;
    memset(&fb, 0, sizeof fb);
    fb.width        = W;
    fb.height       = H;
    fb.pixel_format = 0x34325258U; /* XR24 = XRGB8888 */
    fb.handles[0]   = gem_handle;
    fb.pitches[0]   = pitch;
    if (ioctl(fd, DRM_IOCTL_MODE_ADDFB2, &fb) != 0 || fb.fb_id == 0) {
        fail("addfb2");
        return 1;
    }

    /* Step 9: SETCRTC — blit to the active scanout */
    struct drm_mode_crtc setcrtc;
    memset(&setcrtc, 0, sizeof setcrtc);
    setcrtc.crtc_id            = crtc_id;
    setcrtc.fb_id              = fb.fb_id;
    setcrtc.set_connectors_ptr = (uint64_t)(uintptr_t)&conn_id;
    setcrtc.count_connectors   = 1;
    setcrtc.mode_valid         = 1;
    /* Fill in a minimal mode matching our buffer dimensions */
    setcrtc.mode.hdisplay  = (uint16_t)W;
    setcrtc.mode.vdisplay  = (uint16_t)H;
    setcrtc.mode.htotal    = (uint16_t)(W + 160);
    setcrtc.mode.vtotal    = (uint16_t)(H + 45);
    setcrtc.mode.vrefresh  = 60;
    if (ioctl(fd, DRM_IOCTL_MODE_SETCRTC, &setcrtc) != 0) {
        fail("setcrtc");
        return 1;
    }

    w("drm-ok\n");
    char buf[64];
    int k = snprintf(buf, sizeof buf, "drm-geom %ux%u\n", W, H);
    if (k > 0) write(1, buf, (size_t)k);
    return 0;
}
