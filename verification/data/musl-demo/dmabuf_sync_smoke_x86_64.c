/* dma-buf implicit sync + sync_file ioctls from ring 3.
 *
 * Linux's DMA_BUF_IOCTL_SYNC(START) waits on the buffer's implicit fences
 * with dma_resv_wait_timeout(.., intr = true, MAX_SCHEDULE_TIMEOUT)
 * (drivers/dma-buf/dma-buf.c::__dma_buf_begin_cpu_access). A signal ends
 * that wait with -ERESTARTSYS, and handle_signal (arch/x86/kernel/signal.c)
 * restarts the ioctl when the handler has SA_RESTART and fails it with
 * EINTR otherwise. A kernel test cannot reach that path (no executor to park
 * on, no signal frame), so it is checked here against a real pending fence:
 *
 *   - a virtio-gpu card's atomic commit with OUT_FENCE_PTR yields a sync_file
 *     that signals at the commit's simulated vblank. The first commit after
 *     idle presents "now"; each further commit queues one refresh interval
 *     later, so the last of a burst is pending for a few hundred ms;
 *   - CREATE_DUMB + PRIME_HANDLE_TO_FD give a dma-buf, and
 *     DMA_BUF_IOCTL_IMPORT_SYNC_FILE(WRITE) attaches the pending fence;
 *   - EXPORT_SYNC_FILE(READ) returns that fence: poll() 0 now, POLLIN later;
 *   - SYNC(START|READ) under a 2 ms ITIMER_REAL without SA_RESTART: -1/EINTR
 *     while the fence is still pending;
 *   - the same with SA_RESTART under a 1 ms timer: 0, only after the fence
 *     signalled, with the handler having run during the wait;
 *   - SYNC_IOC_MERGE of two pending fences + SYNC_IOC_FILE_INFO.
 *
 * Success token "dmabuf-sync-ok". The musl-demo fixture carries a
 * virtio-gpu card; a boot without one prints "dmabuf-sync-fail: ..." and no
 * token rather than passing vacuously.
 *
 * Build: see REGEN_dmabuf_sync_smoke.sh (musl-gcc, static-PIE).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DRM_IOCTL_SET_MASTER        0x0000641EU
#define DRM_IOCTL_SET_CLIENT_CAP    0x4010640DU
#define DRM_IOCTL_MODE_GETRESOURCES 0xC04064A0U
#define DRM_IOCTL_MODE_CREATE_DUMB  0xC02064B2U
#define DRM_IOCTL_PRIME_HANDLE_TO_FD 0xC00C642DU
#define DRM_IOCTL_MODE_ATOMIC       0xC03864BCU
#define DRM_CLIENT_CAP_ATOMIC       3ULL
/* NARF's CRTC OUT_FENCE_PTR property id (drm_ioctl_bridge.rs). */
#define CRTC_OUT_FENCE_PTR_PROP_ID  0x60U

#define SYNC_IOC_MERGE              0xC0303E03U
#define SYNC_IOC_FILE_INFO          0xC0383E04U
#define DMA_BUF_IOCTL_SYNC          0x40086200U
#define DMA_BUF_IOCTL_EXPORT_SYNC_FILE 0xC0086202U
#define DMA_BUF_IOCTL_IMPORT_SYNC_FILE 0x40086203U
#define DMA_BUF_SYNC_READ  1ULL
#define DMA_BUF_SYNC_WRITE 2ULL
#define DMA_BUF_SYNC_START 0ULL

struct drm_mode_card_res {
    uint64_t fb_id_ptr, crtc_id_ptr, connector_id_ptr, encoder_id_ptr;
    uint32_t count_fbs, count_crtcs, count_connectors, count_encoders;
    uint32_t min_width, max_width, min_height, max_height;
};
struct drm_mode_create_dumb {
    uint32_t height, width, bpp, flags, handle, pitch;
    uint64_t size;
};
struct drm_prime_handle { uint32_t handle; uint32_t flags; int32_t fd; };
struct drm_mode_atomic {
    uint32_t flags, count_objs;
    uint64_t objs_ptr, count_props_ptr, props_ptr, prop_values_ptr;
    uint64_t reserved, user_data;
};
struct sync_merge_data { char name[32]; int32_t fd2; int32_t fence; uint32_t flags, pad; };
struct sync_fence_info {
    char obj_name[32]; char driver_name[32];
    int32_t status; uint32_t flags; uint64_t timestamp_ns;
};
struct sync_file_info {
    char name[32]; int32_t status; uint32_t flags;
    uint32_t num_fences; uint32_t pad; uint64_t sync_fence_info;
};
struct dma_buf_sync { uint64_t flags; };
struct dma_buf_sync_file { uint32_t flags; int32_t fd; };

static volatile sig_atomic_t alarms;
static void on_alarm(int sig) { (void)sig; alarms++; }

static void w(const char *m) { write(1, m, strlen(m)); }

static int fail(const char *step) {
    char buf[128];
    snprintf(buf, sizeof buf, "dmabuf-sync-fail: %s (errno %d)\n", step, errno);
    w(buf);
    return 1;
}

static int skip(const char *why) {
    w("dmabuf-sync-fail: no pending fence source: ");
    w(why);
    w("\n");
    return 1;
}

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* SYNC_IOC_FILE_INFO with num_fences = 0: status (1 signalled, 0 pending). */
static int fence_status(int fd, uint32_t *count) {
    struct sync_file_info info;
    memset(&info, 0, sizeof info);
    if (ioctl(fd, SYNC_IOC_FILE_INFO, &info) != 0)
        return -100;
    if (count)
        *count = info.num_fences;
    return info.status;
}

static void timer_ms(int ms) {
    struct itimerval it;
    memset(&it, 0, sizeof it);
    it.it_value.tv_usec = ms * 1000;
    it.it_interval.tv_usec = ms * 1000;
    setitimer(ITIMER_REAL, &it, 0);
}

static int set_handler(int flags) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    sa.sa_flags = flags;
    return sigaction(SIGALRM, &sa, 0);
}

/* A burst of OUT_FENCE_PTR commits; returns the last (latest-vblank) fence. */
static int pending_fence(int card, uint32_t crtc, int burst) {
    int last = -1;
    for (int i = 0; i < burst; i++) {
        int32_t out = -1;
        uint32_t objs[1] = { crtc };
        uint32_t counts[1] = { 1 };
        uint32_t props[1] = { CRTC_OUT_FENCE_PTR_PROP_ID };
        uint64_t values[1] = { (uint64_t)(uintptr_t)&out };
        struct drm_mode_atomic req;
        memset(&req, 0, sizeof req);
        req.count_objs = 1;
        req.objs_ptr = (uint64_t)(uintptr_t)objs;
        req.count_props_ptr = (uint64_t)(uintptr_t)counts;
        req.props_ptr = (uint64_t)(uintptr_t)props;
        req.prop_values_ptr = (uint64_t)(uintptr_t)values;
        if (ioctl(card, DRM_IOCTL_MODE_ATOMIC, &req) != 0 || out < 0) {
            if (last >= 0)
                close(last);
            return -1;
        }
        if (last >= 0)
            close(last);
        last = out;
    }
    return last;
}

int main(void) {
    int card = -1;
    uint32_t crtc = 0;
    for (int n = 0; n < 4 && card < 0; n++) {
        char path[32];
        snprintf(path, sizeof path, "/dev/dri/card%d", n);
        int fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd < 0)
            continue;
        (void)ioctl(fd, DRM_IOCTL_SET_MASTER, 0);
        uint64_t cap[2] = { DRM_CLIENT_CAP_ATOMIC, 1 };
        struct drm_mode_card_res res;
        uint32_t crtcs[8];
        memset(&res, 0, sizeof res);
        memset(crtcs, 0, sizeof crtcs);
        res.crtc_id_ptr = (uint64_t)(uintptr_t)crtcs;
        res.count_crtcs = 8;
        if (ioctl(fd, DRM_IOCTL_SET_CLIENT_CAP, cap) == 0
            && ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) == 0 && crtcs[0] != 0) {
            card = fd;
            crtc = crtcs[0];
        } else {
            close(fd);
        }
    }
    if (card < 0)
        return skip("no atomic-capable DRM card");

    int fence = pending_fence(card, crtc, 18);
    if (fence < 0)
        return skip("atomic OUT_FENCE_PTR commit refused");
    if (fence_status(fence, 0) != 0)
        return fail("vblank fence not pending after a commit burst");

    struct drm_mode_create_dumb cd;
    memset(&cd, 0, sizeof cd);
    cd.width = 64;
    cd.height = 64;
    cd.bpp = 32;
    if (ioctl(card, DRM_IOCTL_MODE_CREATE_DUMB, &cd) != 0 || cd.handle == 0)
        return fail("CREATE_DUMB");
    struct drm_prime_handle ph = { cd.handle, O_CLOEXEC | O_RDWR, -1 };
    if (ioctl(card, DRM_IOCTL_PRIME_HANDLE_TO_FD, &ph) != 0 || ph.fd < 0)
        return fail("PRIME_HANDLE_TO_FD");
    int dmabuf = ph.fd;

    struct dma_buf_sync_file imp = { DMA_BUF_SYNC_WRITE, fence };
    if (ioctl(dmabuf, DMA_BUF_IOCTL_IMPORT_SYNC_FILE, &imp) != 0)
        return fail("IMPORT_SYNC_FILE(WRITE)");

    /* (c) EXPORT for READ: the imported write fence, pending now. */
    struct dma_buf_sync_file exp = { DMA_BUF_SYNC_READ, -1 };
    if (ioctl(dmabuf, DMA_BUF_IOCTL_EXPORT_SYNC_FILE, &exp) != 0 || exp.fd < 0)
        return fail("EXPORT_SYNC_FILE(READ)");
    struct pollfd pfd = { exp.fd, POLLIN, 0 };
    if (poll(&pfd, 1, 0) != 0)
        return fail("exported sync_file readable while its fence is pending");

    /* (b) No SA_RESTART: the interrupted START wait fails with EINTR. */
    if (set_handler(0) != 0)
        return fail("sigaction");
    struct dma_buf_sync sync = { DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ };
    alarms = 0;
    timer_ms(2);
    errno = 0;
    int r = ioctl(dmabuf, DMA_BUF_IOCTL_SYNC, &sync);
    int saved = errno;
    timer_ms(0);
    if (r != -1 || saved != EINTR) {
        errno = saved;
        return fail("SYNC(START) without SA_RESTART did not fail with EINTR");
    }
    if (alarms == 0)
        return fail("EINTR without a delivered SIGALRM");
    if (fence_status(fence, 0) != 0)
        return fail("fence signalled before the EINTR case could observe it");

    /* (a) SA_RESTART: the wait restarts across signals until the fence. */
    if (set_handler(SA_RESTART) != 0)
        return fail("sigaction(SA_RESTART)");
    alarms = 0;
    double t0 = now_s();
    timer_ms(1);
    r = ioctl(dmabuf, DMA_BUF_IOCTL_SYNC, &sync);
    saved = errno;
    timer_ms(0);
    double waited = now_s() - t0;
    if (r != 0) {
        errno = saved;
        return fail("SYNC(START) with SA_RESTART did not complete");
    }
    if (fence_status(fence, 0) != 1)
        return fail("SYNC(START) returned before the implicit fence signalled");
    if (alarms == 0)
        return fail("no SIGALRM handled during the restarted wait");

    /* (c) cont.: the exported sync_file now polls readable. */
    pfd.revents = 0;
    if (poll(&pfd, 1, 5000) != 1 || !(pfd.revents & POLLIN))
        return fail("exported sync_file not readable after its fence signalled");

    /* MERGE two pending vblank fences (distinct contexts) + FILE_INFO. */
    int f2 = pending_fence(card, crtc, 4);
    int f3 = pending_fence(card, crtc, 4);
    if (f2 < 0 || f3 < 0)
        return fail("second commit burst");
    struct sync_merge_data md;
    memset(&md, 0, sizeof md);
    strcpy(md.name, "ring3-merge");
    md.fd2 = f3;
    md.fence = -1;
    if (ioctl(f2, SYNC_IOC_MERGE, &md) != 0 || md.fence < 0)
        return fail("SYNC_IOC_MERGE");
    struct sync_fence_info entries[2];
    struct sync_file_info info;
    memset(&info, 0, sizeof info);
    memset(entries, 0, sizeof entries);
    info.num_fences = 2;
    info.sync_fence_info = (uint64_t)(uintptr_t)entries;
    if (ioctl(md.fence, SYNC_IOC_FILE_INFO, &info) != 0)
        return fail("SYNC_IOC_FILE_INFO(merged)");
    if (info.num_fences != 2 || strcmp(info.name, "ring3-merge") != 0
        || strcmp(entries[0].driver_name, "narf_kms") != 0 || entries[0].status != 0)
        return fail("merged FILE_INFO contents");
    struct pollfd mp = { md.fence, POLLIN, 0 };
    if (poll(&mp, 1, 5000) != 1 || fence_status(f2, 0) != 1 || fence_status(f3, 0) != 1)
        return fail("merged sync_file readable before both fences signalled");

    char buf[128];
    snprintf(buf, sizeof buf, "dmabuf-sync-restart waited=%.3fs alarms=%d\n", waited,
             (int)alarms);
    w(buf);
    w("dmabuf-sync-ok\n");
    return 0;
}
