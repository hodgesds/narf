// LD_PRELOAD ioctl recorder for Mesa/libdrm bring-up on NARF.
//
// NARF has no strace-equivalent that follows a non-child tracee, and the
// question the amdgpu uapi workstream needs answered is narrow: which DRM
// ioctls (and which AMDGPU_INFO queries) does Mesa issue while a driver
// initialises, and what does the kernel answer? This shim interposes the
// libc `ioctl` symbol that libdrm and Mesa call through the PLT, forwards
// to the real one, and prints one line per call to stderr:
//
//   IOCTL fd=5 drv=amdgpu AMDGPU_INFO query=DEV_INFO size=432 -> 0
//   IOCTL fd=5 drv=amdgpu AMDGPU_INFO query=HW_IP_INFO ip=GFX inst=0 size=56 -> 0
//   IOCTL fd=5 drv=virtio_gpu VERSION name=virtio_gpu 0.1.0 -> 0
//   IOCTL fd=5 drv=amdgpu GET_CAP cap=SYNCOBJ_TIMELINE val=0 -> 0
//   IOCTL fd=7 drv=? type=0x54 nr=0x13 -> -1 errno=25
//
// The driver name is learned from the DRM_IOCTL_VERSION reply libdrm always
// issues first (drmGetVersion) and keyed by the node's st_rdev, so fds that
// libdrm_amdgpu dup()s afterwards still decode; the shim never issues an
// ioctl of its own and the trace is exactly the application's. Output is formatted
// into a stack buffer and written with one write(2) — no stdio, no locks, no
// allocation — so it is safe in any thread and cannot recurse. Calls that
// bypass the PLT (a raw syscall(SYS_ioctl)) are not seen; Mesa 26.2 and
// libdrm 2.4.134 do not do that on the paths this is used for.
//
// NARF_IOCTL_TRACE=0 silences it without unloading; NARF_IOCTL_TRACE_ALL=1
// also logs non-DRM ioctls (tty, sockets).
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <drm.h>
#include <amdgpu_drm.h>
#include <virtgpu_drm.h>

#define MAX_NODES 64

// st_rdev -> DRM driver name, learned from VERSION replies. Racy only in
// the benign sense: two threads learning the same node write the same name.
static struct {
    dev_t rdev;
    char name[16];
} nodes[MAX_NODES];

static const char *node_driver(int fd)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode))
        return "?";
    for (int i = 0; i < MAX_NODES; i++)
        if (nodes[i].name[0] && nodes[i].rdev == st.st_rdev)
            return nodes[i].name;
    return "?";
}

static void learn_driver(int fd, const char *name, size_t len)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode))
        return;
    if (len > sizeof(nodes[0].name) - 1)
        len = sizeof(nodes[0].name) - 1;
    for (int i = 0; i < MAX_NODES; i++) {
        if (nodes[i].name[0] && nodes[i].rdev != st.st_rdev)
            continue;
        nodes[i].rdev = st.st_rdev;
        memcpy(nodes[i].name, name, len);
        nodes[i].name[len] = 0;
        return;
    }
}
static int trace_on = -1;
static int trace_all;

static const char *core_name(unsigned nr)
{
    switch (nr) {
    case 0x00: return "VERSION";
    case 0x01: return "GET_UNIQUE";
    case 0x02: return "GET_MAGIC";
    case 0x05: return "GET_CLIENT";
    case 0x07: return "SET_VERSION";
    case 0x09: return "GEM_CLOSE";
    case 0x0a: return "GEM_FLINK";
    case 0x0b: return "GEM_OPEN";
    case 0x0c: return "GET_CAP";
    case 0x0d: return "SET_CLIENT_CAP";
    case 0x11: return "AUTH_MAGIC";
    case 0x1e: return "SET_MASTER";
    case 0x1f: return "DROP_MASTER";
    case 0x2d: return "PRIME_HANDLE_TO_FD";
    case 0x2e: return "PRIME_FD_TO_HANDLE";
    case 0x3a: return "WAIT_VBLANK";
    case 0xa0: return "MODE_GETRESOURCES";
    case 0xa1: return "MODE_GETCRTC";
    case 0xa2: return "MODE_SETCRTC";
    case 0xa6: return "MODE_GETENCODER";
    case 0xa7: return "MODE_GETCONNECTOR";
    case 0xaa: return "MODE_GETPROPERTY";
    case 0xac: return "MODE_GETPROPBLOB";
    case 0xad: return "MODE_GETFB";
    case 0xaf: return "MODE_RMFB";
    case 0xb0: return "MODE_PAGE_FLIP";
    case 0xb2: return "MODE_CREATE_DUMB";
    case 0xb3: return "MODE_MAP_DUMB";
    case 0xb4: return "MODE_DESTROY_DUMB";
    case 0xb5: return "MODE_GETPLANERESOURCES";
    case 0xb6: return "MODE_GETPLANE";
    case 0xb8: return "MODE_ADDFB2";
    case 0xb9: return "MODE_OBJ_GETPROPERTIES";
    case 0xbc: return "MODE_ATOMIC";
    case 0xbd: return "MODE_CREATEPROPBLOB";
    case 0xbe: return "MODE_DESTROYPROPBLOB";
    case 0xbf: return "SYNCOBJ_CREATE";
    case 0xc0: return "SYNCOBJ_DESTROY";
    case 0xc1: return "SYNCOBJ_HANDLE_TO_FD";
    case 0xc2: return "SYNCOBJ_FD_TO_HANDLE";
    case 0xc3: return "SYNCOBJ_WAIT";
    case 0xc4: return "SYNCOBJ_RESET";
    case 0xc5: return "SYNCOBJ_SIGNAL";
    case 0xca: return "SYNCOBJ_TIMELINE_WAIT";
    case 0xcb: return "SYNCOBJ_QUERY";
    case 0xcc: return "SYNCOBJ_TRANSFER";
    case 0xcd: return "SYNCOBJ_TIMELINE_SIGNAL";
    case 0xce: return "MODE_GETFB2";
    case 0xcf: return "SYNCOBJ_EVENTFD";
    case 0xd1: return "SET_CLIENT_NAME";
    default: return NULL;
    }
}

static const char *amdgpu_name(unsigned cmd)
{
    static const char *const n[] = {
        [DRM_AMDGPU_GEM_CREATE] = "AMDGPU_GEM_CREATE",
        [DRM_AMDGPU_GEM_MMAP] = "AMDGPU_GEM_MMAP",
        [DRM_AMDGPU_CTX] = "AMDGPU_CTX",
        [DRM_AMDGPU_BO_LIST] = "AMDGPU_BO_LIST",
        [DRM_AMDGPU_CS] = "AMDGPU_CS",
        [DRM_AMDGPU_INFO] = "AMDGPU_INFO",
        [DRM_AMDGPU_GEM_METADATA] = "AMDGPU_GEM_METADATA",
        [DRM_AMDGPU_GEM_WAIT_IDLE] = "AMDGPU_GEM_WAIT_IDLE",
        [DRM_AMDGPU_GEM_VA] = "AMDGPU_GEM_VA",
        [DRM_AMDGPU_WAIT_CS] = "AMDGPU_WAIT_CS",
        [DRM_AMDGPU_GEM_OP] = "AMDGPU_GEM_OP",
        [DRM_AMDGPU_GEM_USERPTR] = "AMDGPU_GEM_USERPTR",
        [DRM_AMDGPU_WAIT_FENCES] = "AMDGPU_WAIT_FENCES",
        [DRM_AMDGPU_VM] = "AMDGPU_VM",
        [DRM_AMDGPU_FENCE_TO_HANDLE] = "AMDGPU_FENCE_TO_HANDLE",
        [DRM_AMDGPU_SCHED] = "AMDGPU_SCHED",
        [DRM_AMDGPU_USERQ] = "AMDGPU_USERQ",
        [DRM_AMDGPU_USERQ_SIGNAL] = "AMDGPU_USERQ_SIGNAL",
        [DRM_AMDGPU_USERQ_WAIT] = "AMDGPU_USERQ_WAIT",
    };
    return cmd < sizeof(n) / sizeof(n[0]) ? n[cmd] : NULL;
}

static const char *virtgpu_name(unsigned cmd)
{
    static const char *const n[] = {
        [DRM_VIRTGPU_MAP] = "VIRTGPU_MAP",
        [DRM_VIRTGPU_EXECBUFFER] = "VIRTGPU_EXECBUFFER",
        [DRM_VIRTGPU_GETPARAM] = "VIRTGPU_GETPARAM",
        [DRM_VIRTGPU_RESOURCE_CREATE] = "VIRTGPU_RESOURCE_CREATE",
        [DRM_VIRTGPU_RESOURCE_INFO] = "VIRTGPU_RESOURCE_INFO",
        [DRM_VIRTGPU_TRANSFER_FROM_HOST] = "VIRTGPU_TRANSFER_FROM_HOST",
        [DRM_VIRTGPU_TRANSFER_TO_HOST] = "VIRTGPU_TRANSFER_TO_HOST",
        [DRM_VIRTGPU_WAIT] = "VIRTGPU_WAIT",
        [DRM_VIRTGPU_GET_CAPS] = "VIRTGPU_GET_CAPS",
        [DRM_VIRTGPU_RESOURCE_CREATE_BLOB] = "VIRTGPU_RESOURCE_CREATE_BLOB",
        [DRM_VIRTGPU_CONTEXT_INIT] = "VIRTGPU_CONTEXT_INIT",
    };
    return cmd < sizeof(n) / sizeof(n[0]) ? n[cmd] : NULL;
}

static const char *info_query_name(unsigned q)
{
    switch (q) {
    case AMDGPU_INFO_ACCEL_WORKING: return "ACCEL_WORKING";
    case AMDGPU_INFO_CRTC_FROM_ID: return "CRTC_FROM_ID";
    case AMDGPU_INFO_HW_IP_INFO: return "HW_IP_INFO";
    case AMDGPU_INFO_HW_IP_COUNT: return "HW_IP_COUNT";
    case AMDGPU_INFO_TIMESTAMP: return "TIMESTAMP";
    case AMDGPU_INFO_FW_VERSION: return "FW_VERSION";
    case AMDGPU_INFO_NUM_BYTES_MOVED: return "NUM_BYTES_MOVED";
    case AMDGPU_INFO_VRAM_USAGE: return "VRAM_USAGE";
    case AMDGPU_INFO_GTT_USAGE: return "GTT_USAGE";
    case AMDGPU_INFO_GDS_CONFIG: return "GDS_CONFIG";
    case AMDGPU_INFO_VRAM_GTT: return "VRAM_GTT";
    case AMDGPU_INFO_READ_MMR_REG: return "READ_MMR_REG";
    case AMDGPU_INFO_DEV_INFO: return "DEV_INFO";
    case AMDGPU_INFO_VIS_VRAM_USAGE: return "VIS_VRAM_USAGE";
    case AMDGPU_INFO_NUM_EVICTIONS: return "NUM_EVICTIONS";
    case AMDGPU_INFO_MEMORY: return "MEMORY";
    case AMDGPU_INFO_VCE_CLOCK_TABLE: return "VCE_CLOCK_TABLE";
    case AMDGPU_INFO_VBIOS: return "VBIOS";
    case AMDGPU_INFO_NUM_HANDLES: return "NUM_HANDLES";
    case AMDGPU_INFO_SENSOR: return "SENSOR";
    case AMDGPU_INFO_NUM_VRAM_CPU_PAGE_FAULTS: return "NUM_VRAM_CPU_PAGE_FAULTS";
    case AMDGPU_INFO_VRAM_LOST_COUNTER: return "VRAM_LOST_COUNTER";
    case AMDGPU_INFO_RAS_ENABLED_FEATURES: return "RAS_ENABLED_FEATURES";
    case AMDGPU_INFO_VIDEO_CAPS: return "VIDEO_CAPS";
    case 0x22: return "MAX_IBS";
    case 0x23: return "GPUVM_FAULT";
    case 0x24: return "UQ_FW_AREAS";
    default: return NULL;
    }
}

static const char *hw_ip_name(unsigned ip)
{
    static const char *const n[] = { "GFX", "COMPUTE", "DMA", "UVD", "VCE",
                                     "UVD_ENC", "VCN_DEC", "VCN_ENC", "VCN_JPEG", "VPE" };
    return ip < sizeof(n) / sizeof(n[0]) ? n[ip] : "?";
}

static const char *fw_name(unsigned t)
{
    static const char *const n[] = {
        "?", "VCE", "UVD", "GMC", "GFX_ME", "GFX_PFP", "GFX_CE", "GFX_RLC", "GFX_MEC",
        "?", "SMC", "SDMA", "SOS", "ASD", "VCN", "RLC_RESTORE_LIST_CNTL",
        "RLC_RESTORE_LIST_GPM_MEM", "RLC_RESTORE_LIST_SRM_MEM", "DMCU", "TA", "DMCUB",
        "TOC", "CAP", "GFX_RLCP", "GFX_RLCV", "MES_KIQ", "MES", "IMU", "VPE",
    };
    return t < sizeof(n) / sizeof(n[0]) ? n[t] : "?";
}

static const char *cap_name(uint64_t c)
{
    switch (c) {
    case DRM_CAP_DUMB_BUFFER: return "DUMB_BUFFER";
    case DRM_CAP_VBLANK_HIGH_CRTC: return "VBLANK_HIGH_CRTC";
    case DRM_CAP_DUMB_PREFERRED_DEPTH: return "DUMB_PREFERRED_DEPTH";
    case DRM_CAP_DUMB_PREFER_SHADOW: return "DUMB_PREFER_SHADOW";
    case DRM_CAP_PRIME: return "PRIME";
    case DRM_CAP_TIMESTAMP_MONOTONIC: return "TIMESTAMP_MONOTONIC";
    case DRM_CAP_ASYNC_PAGE_FLIP: return "ASYNC_PAGE_FLIP";
    case DRM_CAP_CURSOR_WIDTH: return "CURSOR_WIDTH";
    case DRM_CAP_CURSOR_HEIGHT: return "CURSOR_HEIGHT";
    case DRM_CAP_ADDFB2_MODIFIERS: return "ADDFB2_MODIFIERS";
    case DRM_CAP_PAGE_FLIP_TARGET: return "PAGE_FLIP_TARGET";
    case DRM_CAP_CRTC_IN_VBLANK_EVENT: return "CRTC_IN_VBLANK_EVENT";
    case DRM_CAP_SYNCOBJ: return "SYNCOBJ";
    case DRM_CAP_SYNCOBJ_TIMELINE: return "SYNCOBJ_TIMELINE";
    default: return "?";
    }
}

struct out {
    char buf[512];
    size_t n;
};

static void put(struct out *o, const char *fmt, ...)
{
    if (o->n >= sizeof(o->buf))
        return;
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(o->buf + o->n, sizeof(o->buf) - o->n, fmt, ap);
    va_end(ap);
    if (w > 0)
        o->n += (size_t)w < sizeof(o->buf) - o->n ? (size_t)w : sizeof(o->buf) - o->n - 1;
}

// Request details that are only meaningful BEFORE the call (inputs).
static void describe_in(struct out *o, const char *drv, unsigned type, unsigned nr, void *arg)
{
    if (type != DRM_IOCTL_BASE)
        return;
    if (nr == 0x0c && arg) {
        put(o, " cap=%s", cap_name(((struct drm_get_cap *)arg)->capability));
        return;
    }
    if (nr == 0x0d && arg) {
        put(o, " cap=%llu val=%llu", (unsigned long long)((struct drm_set_client_cap *)arg)->capability,
            (unsigned long long)((struct drm_set_client_cap *)arg)->value);
        return;
    }
    if (nr < DRM_COMMAND_BASE || nr >= DRM_COMMAND_END || !arg)
        return;
    unsigned cmd = nr - DRM_COMMAND_BASE;
    if (strcmp(drv, "amdgpu") == 0) {
        if (cmd == DRM_AMDGPU_INFO) {
            struct drm_amdgpu_info *i = arg;
            const char *q = info_query_name(i->query);
            if (q)
                put(o, " query=%s", q);
            else
                put(o, " query=0x%x", i->query);
            switch (i->query) {
            case AMDGPU_INFO_HW_IP_INFO:
            case AMDGPU_INFO_HW_IP_COUNT:
                put(o, " ip=%s inst=%u", hw_ip_name(i->query_hw_ip.type), i->query_hw_ip.ip_instance);
                break;
            case AMDGPU_INFO_FW_VERSION:
                put(o, " fw=%s inst=%u index=%u", fw_name(i->query_fw.fw_type), i->query_fw.ip_instance,
                    i->query_fw.index);
                break;
            case AMDGPU_INFO_READ_MMR_REG:
                put(o, " reg=0x%x count=%u instance=0x%x", i->read_mmr_reg.dword_offset,
                    i->read_mmr_reg.count, i->read_mmr_reg.instance);
                break;
            case AMDGPU_INFO_SENSOR:
                put(o, " sensor=%u", i->sensor_info.type);
                break;
            case AMDGPU_INFO_VIDEO_CAPS:
                put(o, " video=%u", i->video_cap.type);
                break;
            case AMDGPU_INFO_VBIOS:
                put(o, " vbios=%u", i->vbios_info.type);
                break;
            }
            put(o, " size=%u", i->return_size);
        } else if (cmd == DRM_AMDGPU_CTX) {
            union drm_amdgpu_ctx *c = arg;
            put(o, " op=%u", c->in.op);
            if (c->in.op == AMDGPU_CTX_OP_ALLOC_CTX)
                put(o, " prio=%d", c->in.priority);
            else
                put(o, " ctx=%u", c->in.ctx_id);
        } else if (cmd == DRM_AMDGPU_GEM_CREATE) {
            union drm_amdgpu_gem_create *g = arg;
            put(o, " size=%llu align=%llu domains=0x%llx flags=0x%llx", (unsigned long long)g->in.bo_size,
                (unsigned long long)g->in.alignment, (unsigned long long)g->in.domains,
                (unsigned long long)g->in.domain_flags);
        } else if (cmd == DRM_AMDGPU_GEM_VA) {
            struct drm_amdgpu_gem_va *v = arg;
            put(o, " op=%u handle=%u flags=0x%x va=0x%llx size=0x%llx", v->operation, v->handle, v->flags,
                (unsigned long long)v->va_address, (unsigned long long)v->map_size);
        } else if (cmd == DRM_AMDGPU_GEM_METADATA) {
            put(o, " op=%u handle=%u", ((struct drm_amdgpu_gem_metadata *)arg)->op,
                ((struct drm_amdgpu_gem_metadata *)arg)->handle);
        } else if (cmd == DRM_AMDGPU_GEM_OP) {
            put(o, " op=%u handle=%u", ((struct drm_amdgpu_gem_op *)arg)->op,
                ((struct drm_amdgpu_gem_op *)arg)->handle);
        } else if (cmd == DRM_AMDGPU_CS) {
            union drm_amdgpu_cs *cs = arg;
            put(o, " ctx=%u chunks=%u ids=", cs->in.ctx_id, cs->in.num_chunks);
            const uint64_t *ptrs = (const uint64_t *)(uintptr_t)cs->in.chunks;
            for (unsigned c = 0; ptrs && c < cs->in.num_chunks && c < 16; c++) {
                const struct drm_amdgpu_cs_chunk *ch = (const void *)(uintptr_t)ptrs[c];
                if (ch)
                    put(o, "%s%u", c ? "," : "", ch->chunk_id);
            }
        } else if (cmd == DRM_AMDGPU_VM) {
            put(o, " op=%u", ((union drm_amdgpu_vm *)arg)->in.op);
        }
    } else if (strcmp(drv, "virtio_gpu") == 0 && cmd == DRM_VIRTGPU_GETPARAM) {
        put(o, " param=%llu", (unsigned long long)((struct drm_virtgpu_getparam *)arg)->param);
    } else if (strcmp(drv, "virtio_gpu") == 0 && cmd == DRM_VIRTGPU_GET_CAPS) {
        put(o, " capset=%u ver=%u", ((struct drm_virtgpu_get_caps *)arg)->cap_set_id,
            ((struct drm_virtgpu_get_caps *)arg)->cap_set_ver);
    }
}

// Replies worth recording (outputs), printed only on success.
static void describe_out(struct out *o, int fd, const char *drv, unsigned type, unsigned nr, void *arg,
                         uint32_t in_op)
{
    if (type != DRM_IOCTL_BASE || !arg)
        return;
    if (nr == 0x00) {
        struct drm_version *v = arg;
        // libdrm calls VERSION twice: once for the lengths (name == NULL),
        // once with buffers. Only the second carries the name.
        if (v->name && v->name_len > 0) {
            size_t n = v->name_len < 16 ? v->name_len : 16;
            learn_driver(fd, v->name, n);
            put(o, " name=%.*s", (int)n, v->name);
        }
        put(o, " %d.%d.%d", v->version_major, v->version_minor, v->version_patchlevel);
        return;
    }
    if (nr == 0x0c) {
        put(o, " val=%llu", (unsigned long long)((struct drm_get_cap *)arg)->value);
        return;
    }
    if (nr < DRM_COMMAND_BASE || nr >= DRM_COMMAND_END || strcmp(drv, "amdgpu") != 0)
        return;
    unsigned cmd = nr - DRM_COMMAND_BASE;
    if (cmd == DRM_AMDGPU_INFO) {
        struct drm_amdgpu_info *i = arg;
        const uint32_t *r = (const uint32_t *)(uintptr_t)i->return_pointer;
        if (r && i->return_size >= 4 &&
            (i->query == AMDGPU_INFO_ACCEL_WORKING || i->query == AMDGPU_INFO_HW_IP_COUNT ||
             i->query == AMDGPU_INFO_READ_MMR_REG))
            put(o, " val=0x%x", r[0]);
        if (r && i->return_size >= 8 && i->query == AMDGPU_INFO_FW_VERSION)
            put(o, " ver=0x%x feature=%u", r[0], r[1]);
        if (r && i->query == AMDGPU_INFO_HW_IP_INFO && i->return_size >= sizeof(struct drm_amdgpu_info_hw_ip)) {
            const struct drm_amdgpu_info_hw_ip *h = (const void *)r;
            put(o, " ver=%u.%u rings=0x%x ib_align=%u/%u", h->hw_ip_version_major, h->hw_ip_version_minor,
                h->available_rings, h->ib_start_alignment, h->ib_size_alignment);
        }
        if (r && i->query == AMDGPU_INFO_DEV_INFO && i->return_size >= 48) {
            const struct drm_amdgpu_info_device *d = (const void *)r;
            put(o, " dev=0x%x rev=0x%x ext=0x%x family=%u", d->device_id, d->chip_rev, d->external_rev, d->family);
        }
    } else if (cmd == DRM_AMDGPU_CTX) {
        // The reply overwrites the request union; only ALLOC returns an id.
        if (in_op == AMDGPU_CTX_OP_ALLOC_CTX)
            put(o, " ctx=%u", ((union drm_amdgpu_ctx *)arg)->out.alloc.ctx_id);
    } else if (cmd == DRM_AMDGPU_GEM_CREATE) {
        put(o, " handle=%u", ((union drm_amdgpu_gem_create *)arg)->out.handle);
    } else if (cmd == DRM_AMDGPU_CS) {
        put(o, " seq=%llu", (unsigned long long)((union drm_amdgpu_cs *)arg)->out.handle);
    }
}

#ifdef __GLIBC__
int ioctl(int fd, unsigned long req, ...)
#else
int ioctl(int fd, int req, ...)
#endif
{
    static int (*real)(int, unsigned long, ...);
    va_list ap;
    va_start(ap, req);
    void *arg = va_arg(ap, void *);
    va_end(ap);

    if (!real) {
        real = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT, "ioctl");
        if (!real) {
            errno = ENOSYS;
            return -1;
        }
    }
    if (trace_on < 0) {
        const char *e = getenv("NARF_IOCTL_TRACE");
        trace_on = !(e && e[0] == '0');
        e = getenv("NARF_IOCTL_TRACE_ALL");
        trace_all = e && e[0] == '1';
    }

    unsigned r = (unsigned)req;
    unsigned type = _IOC_TYPE(r), nr = _IOC_NR(r);
    if (!trace_on || (type != DRM_IOCTL_BASE && !trace_all))
        return real(fd, (unsigned long)r, arg);

    const char *drv = type == DRM_IOCTL_BASE ? node_driver(fd) : "-";
    struct out o = { .n = 0 };
    put(&o, "IOCTL pid=%d fd=%d drv=%s ", (int)getpid(), fd, drv);
    const char *name = NULL;
    int driver_cmd = nr >= DRM_COMMAND_BASE && nr < DRM_COMMAND_END;
    if (type == DRM_IOCTL_BASE && !driver_cmd)
        name = core_name(nr);
    else if (type == DRM_IOCTL_BASE && strcmp(drv, "amdgpu") == 0)
        name = amdgpu_name(nr - DRM_COMMAND_BASE);
    else if (type == DRM_IOCTL_BASE && strcmp(drv, "virtio_gpu") == 0)
        name = virtgpu_name(nr - DRM_COMMAND_BASE);
    if (name)
        put(&o, "%s", name);
    else
        put(&o, "type=0x%x nr=0x%x", type, nr);
    describe_in(&o, drv, type, nr, arg);

    // First request word (CTX op etc.), captured before the reply
    // overwrites the in/out union.
    uint32_t in_op = (type == DRM_IOCTL_BASE && arg && _IOC_SIZE(r) >= 4) ? *(const uint32_t *)arg : 0;
    int ret = real(fd, (unsigned long)r, arg);
    int err = errno;
    if (ret >= 0)
        describe_out(&o, fd, drv, type, nr, arg, in_op);
    if (ret < 0)
        put(&o, " -> %d errno=%d\n", ret, err);
    else
        put(&o, " -> %d\n", ret);
    if (o.n >= sizeof(o.buf))
        o.n = sizeof(o.buf) - 1;
    if (o.buf[o.n - 1] != '\n')
        o.buf[o.n - 1] = '\n';
    (void)!write(2, o.buf, o.n);
    errno = err;
    return ret;
}
