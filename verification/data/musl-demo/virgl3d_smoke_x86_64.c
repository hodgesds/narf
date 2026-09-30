// virgl3d_smoke: prove REAL 3D rendering through the whole stack —
// /dev/dri/renderD128 → NARF VIRTGPU ioctls → virtio-gpu-gl controlq →
// host virglrenderer → host GPU — with a pixel readback check.
//
// The command stream is hand-rolled VirGL protocol (no Mesa in the loop):
//   1. RESOURCE_CREATE a 64x64 B8G8R8A8 render target with guest backing
//   2. EXECBUFFER: CREATE_OBJECT(SURFACE) + SET_FRAMEBUFFER_STATE + CLEAR
//      to (0.25, 0.5, 0.75, 1.0)
//   3. TRANSFER_FROM_HOST_3D the rendered texture into the guest pages
//   4. VIRTGPU_WAIT, VIRTGPU_MAP + mmap, verify the cleared pixels
//   5. draw a fullscreen triangle from a classic RESOURCE_CREATE vertex buffer
//   6. draw it again from a HOST3D blob vertex buffer, created the way Mesa's
//      virgl winsys creates MAP_PERSISTENT buffers (RESOURCE_CREATE_BLOB with
//      an embedded PIPE_RESOURCE_CREATE, then MAP + mmap to fill it). Linux's
//      virtio_gpu_gem_object_open CTX_ATTACHes every new handle, blobs
//      included; a blob the context never had attached is "Illegal resource"
//      to virglrenderer and the draw is dropped (skipped without host-visible
//      blob support)
//
// Constant provenance (do not guess these):
//   - virgl protocol: mesa src/virtio/virtio-gpu/virgl_protocol.h
//     (VIRGL_CMD0, CCMD_CREATE_OBJECT=1 / SET_FRAMEBUFFER_STATE=5 / CLEAR=7,
//      VIRGL_OBJECT_SURFACE=8, payload dword layouts)
//   - formats: virgl_hw.h VIRGL_FORMAT_B8G8R8A8_UNORM=1
//   - gallium: p_defines.h PIPE_TEXTURE_2D=2, PIPE_BIND_RENDER_TARGET=1<<1,
//     PIPE_BIND_SAMPLER_VIEW=1<<3, PIPE_CLEAR_COLOR0=1<<2
//   - uapi: linux include/uapi/drm/virtgpu_drm.h struct layouts
//
// On a host without 3D (plain virtio-gpu / bochs) the test SKIPS, so the
// same binary is safe in the always-on demo matrix: GETPARAM(3D_FEATURES)
// is the Linux-defined probe for this.
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

// ── DRM_IOCTL_VIRTGPU_* (drm_command_base 0x40, type 'd') ──
#define IOC_RW(nr, sz) ((3u << 30) | ((uint32_t)(sz) << 16) | (0x64u << 8) | (nr))

struct vg_map { uint64_t offset; uint32_t handle, pad; };
struct vg_execbuffer {
    uint32_t flags, size;
    uint64_t command, bo_handles;
    uint32_t num_bo_handles;
    int32_t fence_fd;
    uint32_t ring_idx, syncobj_stride, num_in_syncobjs, num_out_syncobjs;
    uint64_t in_syncobjs, out_syncobjs;
};
struct vg_getparam { uint64_t param, value; };
struct vg_resource_create {
    uint32_t target, format, bind, width, height, depth, array_size,
        last_level, nr_samples, flags, bo_handle, res_handle, size, stride;
};
struct vg_transfer {
    uint32_t bo_handle;
    uint32_t x, y, z, w, h, d;
    uint32_t level, offset, stride, layer_stride;
};
struct vg_wait { uint32_t handle, flags; };
struct vg_get_caps { uint32_t cap_set_id, cap_set_ver; uint64_t addr; uint32_t size, pad; };
struct vg_resource_create_blob {
    uint32_t blob_mem, blob_flags, bo_handle, res_handle;
    uint64_t size;
    uint32_t pad, cmd_size;
    uint64_t cmd, blob_id;
};

#define VIRTGPU_MAP IOC_RW(0x41, sizeof(struct vg_map))
#define VIRTGPU_EXECBUFFER IOC_RW(0x42, sizeof(struct vg_execbuffer))
#define VIRTGPU_GETPARAM IOC_RW(0x43, sizeof(struct vg_getparam))
#define VIRTGPU_RESOURCE_CREATE IOC_RW(0x44, sizeof(struct vg_resource_create))
#define VIRTGPU_TRANSFER_FROM_HOST IOC_RW(0x46, sizeof(struct vg_transfer))
#define VIRTGPU_WAIT IOC_RW(0x48, sizeof(struct vg_wait))
#define VIRTGPU_GET_CAPS IOC_RW(0x49, sizeof(struct vg_get_caps))
#define VIRTGPU_RESOURCE_CREATE_BLOB IOC_RW(0x4a, sizeof(struct vg_resource_create_blob))

#define PARAM_3D_FEATURES 1
#define PARAM_RESOURCE_BLOB 3
#define PARAM_HOST_VISIBLE 4
#define BLOB_MEM_HOST3D 2
#define BLOB_FLAG_USE_MAPPABLE 1

// ── VirGL protocol ──
#define VIRGL_CMD0(cmd, obj, len) ((cmd) | ((obj) << 8) | ((uint32_t)(len) << 16))
#define CCMD_CREATE_OBJECT 1
#define CCMD_BIND_OBJECT 2
#define CCMD_SET_VIEWPORT_STATE 4
#define CCMD_SET_FRAMEBUFFER_STATE 5
#define CCMD_SET_VERTEX_BUFFERS 6
#define CCMD_CLEAR 7
#define CCMD_DRAW_VBO 8
#define CCMD_RESOURCE_INLINE_WRITE 9
#define CCMD_BIND_SHADER 31
#define CCMD_PIPE_RESOURCE_CREATE 48
#define OBJ_BLEND 1
#define OBJ_RASTERIZER 2
#define OBJ_DSA 3
#define OBJ_SHADER 4
#define OBJ_VERTEX_ELEMENTS 5
#define OBJ_SURFACE 8

#define VIRGL_FORMAT_B8G8R8A8_UNORM 1
#define VIRGL_FORMAT_R32G32B32A32_FLOAT 31
#define VIRGL_FORMAT_R8_UNORM 64
#define VIRGL_RESOURCE_FLAG_MAP_PERSISTENT (1u << 1)
#define PIPE_BUFFER 0
#define PIPE_TEXTURE_2D 2
#define PIPE_BIND_RENDER_TARGET (1u << 1)
#define PIPE_BIND_SAMPLER_VIEW (1u << 3)
#define PIPE_BIND_VERTEX_BUFFER (1u << 4)
#define PIPE_CLEAR_COLOR0 (1u << 2)
#define PIPE_PRIM_TRIANGLES 4

#define W 64
#define H 64

static uint32_t f2u(float f) { uint32_t u; memcpy(&u, &f, 4); return u; }
static int close_enough(int a, int b) { return a - b <= 2 && b - a <= 2; }

// Probe the corners + center of the BGRA image for one expected color.
static int check_pixels(const uint8_t *px, int b, int g, int r, int a, const char *tag)
{
    const unsigned probes[] = { 0, (W - 1) * 4, ((H - 1) * W) * 4,
                                ((H - 1) * W + W - 1) * 4, ((H / 2) * W + W / 2) * 4 };
    int bad = 0;
    for (unsigned i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        const uint8_t *p = px + probes[i];
        if (!close_enough(p[0], b) || !close_enough(p[1], g) ||
            !close_enough(p[2], r) || !close_enough(p[3], a)) {
            printf("virgl3d-fail %s pixel@%u = %02x%02x%02x%02x (BGRA)\n",
                   tag, probes[i] / 4, p[0], p[1], p[2], p[3]);
            bad = 1;
        }
    }
    return bad;
}

// Append a CREATE_OBJECT(SHADER) carrying TGSI text; returns new stream pos.
static unsigned emit_shader(uint32_t *cmds, unsigned n, uint32_t handle,
                            uint32_t shader_type, const char *tgsi)
{
    const uint32_t text_len = (uint32_t)strlen(tgsi) + 1; // include NUL
    const uint32_t text_dwords = (text_len + 3) / 4;
    // Header (VIRGL_OBJ_SHADER_HDR_SIZE with zero stream-out outputs = 5)
    // + text, all counted in the CMD0 length.
    cmds[n++] = VIRGL_CMD0(CCMD_CREATE_OBJECT, OBJ_SHADER, 5 + text_dwords);
    cmds[n++] = handle;
    cmds[n++] = shader_type;            // PIPE_SHADER_VERTEX=0 / FRAGMENT=1
    cmds[n++] = text_len;               // offlen: bytes in this chunk
    cmds[n++] = 300;                    // num_tokens upper bound (text-parsed)
    cmds[n++] = 0;                      // so_num_outputs
    memset(&cmds[n], 0, text_dwords * 4);
    memcpy(&cmds[n], tgsi, text_len);
    return n + text_dwords;
}

int main(void)
{
    int fd = open("/dev/dri/renderD128", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("virgl3d-skip no-render-node errno=%d\n", errno);
        printf("virgl3d-done\n");
        return 0;
    }

    // Linux writes the result through the value POINTER (sizeof(int)).
    uint64_t features = 0;
    struct vg_getparam gp = { .param = PARAM_3D_FEATURES,
                              .value = (uint64_t)(uintptr_t)&features };
    if (ioctl(fd, VIRTGPU_GETPARAM, &gp) || !features) {
        printf("virgl3d-skip no-3d errno=%d features=%llu\n", errno,
               (unsigned long long)features);
        printf("virgl3d-done\n");
        return 0;
    }

    // Capset sanity: classic VirGL is capset 1 (v1) / 2 (v2); ask for 2
    // first and fall back to 1. A kernel that filters unadvertised capsets
    // (NARF, Linux) answers EINVAL for a missing one.
    static uint8_t caps[4096];
    struct vg_get_caps gc = { .cap_set_id = 2, .cap_set_ver = 2,
                              .addr = (uint64_t)(uintptr_t)caps, .size = sizeof(caps) };
    if (ioctl(fd, VIRTGPU_GET_CAPS, &gc)) {
        gc.cap_set_id = 1;
        gc.cap_set_ver = 1;
        if (ioctl(fd, VIRTGPU_GET_CAPS, &gc)) {
            printf("virgl3d-fail get-caps errno=%d\n", errno);
            return 1;
        }
    }
    int caps_nonzero = 0;
    for (unsigned i = 0; i < sizeof(caps); i++) caps_nonzero |= caps[i];
    printf("virgl3d: capset=%u nonzero=%d\n", gc.cap_set_id, !!caps_nonzero);

    struct vg_resource_create rc = {
        .target = PIPE_TEXTURE_2D,
        .format = VIRGL_FORMAT_B8G8R8A8_UNORM,
        .bind = PIPE_BIND_RENDER_TARGET | PIPE_BIND_SAMPLER_VIEW,
        .width = W, .height = H, .depth = 1, .array_size = 1,
        .size = W * H * 4,
    };
    if (ioctl(fd, VIRTGPU_RESOURCE_CREATE, &rc)) {
        printf("virgl3d-fail resource-create errno=%d\n", errno);
        return 1;
    }
    printf("virgl3d: bo=%u res=%u\n", rc.bo_handle, rc.res_handle);

    // VirGL stream: surface object → framebuffer state → clear.
    uint32_t cmds[1 + 5 + 1 + 3 + 1 + 8];
    unsigned n = 0;
    const uint32_t surf_handle = 1;
    cmds[n++] = VIRGL_CMD0(CCMD_CREATE_OBJECT, OBJ_SURFACE, 5);
    cmds[n++] = surf_handle;      // VIRGL_OBJ_CREATE_HANDLE
    cmds[n++] = rc.res_handle;    // VIRGL_OBJ_SURFACE_RES_HANDLE
    cmds[n++] = VIRGL_FORMAT_B8G8R8A8_UNORM; // VIRGL_OBJ_SURFACE_FORMAT
    cmds[n++] = 0;                // TEXTURE_LEVEL
    cmds[n++] = 0;                // TEXTURE_LAYERS (first=last=0)
    cmds[n++] = VIRGL_CMD0(CCMD_SET_FRAMEBUFFER_STATE, 0, 3);
    cmds[n++] = 1;                // nr_cbufs
    cmds[n++] = 0;                // zsurf handle (none)
    cmds[n++] = surf_handle;      // cbuf[0]
    cmds[n++] = VIRGL_CMD0(CCMD_CLEAR, 0, 8);
    cmds[n++] = PIPE_CLEAR_COLOR0;
    cmds[n++] = f2u(0.25f);       // R
    cmds[n++] = f2u(0.50f);       // G
    cmds[n++] = f2u(0.75f);       // B
    cmds[n++] = f2u(1.00f);       // A
    cmds[n++] = 0;                // depth (double, lo)
    cmds[n++] = 0;                // depth (double, hi)
    cmds[n++] = 0;                // stencil

    struct vg_execbuffer eb = {
        .size = n * 4,
        .command = (uint64_t)(uintptr_t)cmds,
        .bo_handles = (uint64_t)(uintptr_t)&rc.bo_handle,
        .num_bo_handles = 1,
        .fence_fd = -1,
    };
    if (ioctl(fd, VIRTGPU_EXECBUFFER, &eb)) {
        printf("virgl3d-fail execbuffer errno=%d\n", errno);
        return 1;
    }

    struct vg_transfer tf = {
        .bo_handle = rc.bo_handle,
        .w = W, .h = H, .d = 1,
    };
    if (ioctl(fd, VIRTGPU_TRANSFER_FROM_HOST, &tf)) {
        printf("virgl3d-fail transfer-from-host errno=%d\n", errno);
        return 1;
    }

    struct vg_wait wt = { .handle = rc.bo_handle };
    if (ioctl(fd, VIRTGPU_WAIT, &wt)) {
        printf("virgl3d-fail wait errno=%d\n", errno);
        return 1;
    }

    struct vg_map mp = { .handle = rc.bo_handle };
    if (ioctl(fd, VIRTGPU_MAP, &mp)) {
        printf("virgl3d-fail map errno=%d\n", errno);
        return 1;
    }
    uint8_t *px = mmap(NULL, W * H * 4, PROT_READ, MAP_SHARED, fd, (off_t)mp.offset);
    if (px == MAP_FAILED) {
        printf("virgl3d-fail mmap errno=%d\n", errno);
        return 1;
    }

    // B8G8R8A8_UNORM in memory: B, G, R, A. Expect (R,G,B,A) =
    // (0.25, 0.5, 0.75, 1.0) → (64, 128, 191, 255) with UNORM rounding slop.
    printf("virgl3d: clear bgra=%02x%02x%02x%02x\n", px[0], px[1], px[2], px[3]);
    if (check_pixels(px, 191, 128, 64, 255, "clear"))
        return 1;

    // ── Phase 2: a real shaded triangle through the full pipeline ──
    // Vertex buffer: an oversized clip-space triangle covering the whole
    // viewport, so rasterization must touch every probe.
    struct vg_resource_create vb = {
        .target = PIPE_BUFFER,
        .bind = PIPE_BIND_VERTEX_BUFFER,
        .width = 48, .height = 1, .depth = 1, .array_size = 1,
        .size = 48,
    };
    if (ioctl(fd, VIRTGPU_RESOURCE_CREATE, &vb)) {
        printf("virgl3d-fail vbo-create errno=%d\n", errno);
        return 1;
    }

    static uint32_t dc[512];
    unsigned m = 0;
    // Upload 3 × vec4 f32 vertices inline: (-1,-1) (3,-1) (-1,3).
    dc[m++] = VIRGL_CMD0(CCMD_RESOURCE_INLINE_WRITE, 0, 11 + 12);
    dc[m++] = vb.res_handle; // res
    dc[m++] = 0;             // level
    dc[m++] = 0;             // usage
    dc[m++] = 0;             // stride
    dc[m++] = 0;             // layer_stride
    dc[m++] = 0;             // x
    dc[m++] = 0;             // y
    dc[m++] = 0;             // z
    dc[m++] = 48;            // w (bytes for a buffer box)
    dc[m++] = 1;             // h
    dc[m++] = 1;             // d
    const float verts[12] = { -1, -1, 0, 1, 3, -1, 0, 1, -1, 3, 0, 1 };
    for (int i = 0; i < 12; i++) dc[m++] = f2u(verts[i]);

    // Vertex elements: one vec4 float attribute from buffer 0.
    const uint32_t ve_handle = 2;
    dc[m++] = VIRGL_CMD0(CCMD_CREATE_OBJECT, OBJ_VERTEX_ELEMENTS, 5);
    dc[m++] = ve_handle;
    dc[m++] = 0;  // src_offset
    dc[m++] = 0;  // instance_divisor
    dc[m++] = 0;  // vertex_buffer_index
    dc[m++] = VIRGL_FORMAT_R32G32B32A32_FLOAT;
    dc[m++] = VIRGL_CMD0(CCMD_BIND_OBJECT, OBJ_VERTEX_ELEMENTS, 1);
    dc[m++] = ve_handle;

    dc[m++] = VIRGL_CMD0(CCMD_SET_VERTEX_BUFFERS, 0, 3);
    dc[m++] = 16;            // stride
    dc[m++] = 0;             // offset
    dc[m++] = vb.res_handle;

    // Shaders: TGSI text, exactly what Mesa's virgl driver transports.
    const uint32_t vs_handle = 3, fs_handle = 4;
    m = emit_shader(dc, m, vs_handle, 0,
                    "VERT\n"
                    "DCL IN[0]\n"
                    "DCL OUT[0], POSITION\n"
                    "  0: MOV OUT[0], IN[0]\n"
                    "  1: END\n");
    m = emit_shader(dc, m, fs_handle, 1,
                    "FRAG\n"
                    "DCL OUT[0], COLOR\n"
                    "IMM[0] FLT32 {0.0000, 1.0000, 0.0000, 1.0000}\n"
                    "  0: MOV OUT[0], IMM[0]\n"
                    "  1: END\n");
    dc[m++] = VIRGL_CMD0(CCMD_BIND_SHADER, 0, 2);
    dc[m++] = vs_handle;
    dc[m++] = 0; // PIPE_SHADER_VERTEX
    dc[m++] = VIRGL_CMD0(CCMD_BIND_SHADER, 0, 2);
    dc[m++] = fs_handle;
    dc[m++] = 1; // PIPE_SHADER_FRAGMENT

    // Blend (colormask 0xf on RT0), DSA (all off), rasterizer (cull off,
    // depth_clip on, fill solid) — the minimal fixed-function trio.
    const uint32_t blend_handle = 5, dsa_handle = 6, rs_handle = 7;
    dc[m++] = VIRGL_CMD0(CCMD_CREATE_OBJECT, OBJ_BLEND, 11);
    dc[m++] = blend_handle;
    dc[m++] = 0;                 // S0
    dc[m++] = 0;                 // S1
    dc[m++] = 0xfu << 27;        // S2[0]: RT0 colormask = RGBA
    for (int i = 1; i < 8; i++) dc[m++] = 0; // S2[1..7]
    dc[m++] = VIRGL_CMD0(CCMD_BIND_OBJECT, OBJ_BLEND, 1);
    dc[m++] = blend_handle;
    dc[m++] = VIRGL_CMD0(CCMD_CREATE_OBJECT, OBJ_DSA, 5);
    dc[m++] = dsa_handle;
    dc[m++] = 0; // S0: depth disabled
    dc[m++] = 0; // S1
    dc[m++] = 0; // S2
    dc[m++] = 0; // alpha ref
    dc[m++] = VIRGL_CMD0(CCMD_BIND_OBJECT, OBJ_DSA, 1);
    dc[m++] = dsa_handle;
    dc[m++] = VIRGL_CMD0(CCMD_CREATE_OBJECT, OBJ_RASTERIZER, 9);
    dc[m++] = rs_handle;
    dc[m++] = (1u << 1) | (1u << 29); // S0: depth_clip | half_pixel_center
    dc[m++] = f2u(1.0f);              // point size
    dc[m++] = 0;                      // sprite coord enable
    dc[m++] = 0;                      // S3
    dc[m++] = f2u(1.0f);              // line width
    dc[m++] = 0;                      // offset units
    dc[m++] = 0;                      // offset scale
    dc[m++] = 0;                      // offset clamp
    dc[m++] = VIRGL_CMD0(CCMD_BIND_OBJECT, OBJ_RASTERIZER, 1);
    dc[m++] = rs_handle;

    // Viewport mapping NDC → 64x64 (FBO orientation, no y-flip).
    dc[m++] = VIRGL_CMD0(CCMD_SET_VIEWPORT_STATE, 0, 7);
    dc[m++] = 0; // start slot
    dc[m++] = f2u(W / 2.0f);
    dc[m++] = f2u(H / 2.0f);
    dc[m++] = f2u(0.5f);
    dc[m++] = f2u(W / 2.0f);
    dc[m++] = f2u(H / 2.0f);
    dc[m++] = f2u(0.5f);

    // Framebuffer state persists per (sub-)context, but re-set it so the
    // draw phase stands alone.
    dc[m++] = VIRGL_CMD0(CCMD_SET_FRAMEBUFFER_STATE, 0, 3);
    dc[m++] = 1;
    dc[m++] = 0;
    dc[m++] = 1; // surf_handle from phase 1

    dc[m++] = VIRGL_CMD0(CCMD_DRAW_VBO, 0, 12);
    dc[m++] = 0;                    // start
    dc[m++] = 3;                    // count
    dc[m++] = PIPE_PRIM_TRIANGLES;  // mode
    dc[m++] = 0;                    // indexed
    dc[m++] = 1;                    // instance_count
    dc[m++] = 0;                    // index_bias
    dc[m++] = 0;                    // start_instance
    dc[m++] = 0;                    // primitive_restart
    dc[m++] = 0;                    // restart_index
    dc[m++] = 0;                    // min_index
    dc[m++] = 2;                    // max_index
    dc[m++] = 0;                    // cso (count_from_so)

    uint32_t bos[2] = { rc.bo_handle, vb.bo_handle };
    struct vg_execbuffer eb2 = {
        .size = m * 4,
        .command = (uint64_t)(uintptr_t)dc,
        .bo_handles = (uint64_t)(uintptr_t)bos,
        .num_bo_handles = 2,
        .fence_fd = -1,
    };
    if (ioctl(fd, VIRTGPU_EXECBUFFER, &eb2)) {
        printf("virgl3d-fail draw-execbuffer errno=%d\n", errno);
        return 1;
    }
    if (ioctl(fd, VIRTGPU_TRANSFER_FROM_HOST, &tf)) {
        printf("virgl3d-fail draw-transfer errno=%d\n", errno);
        return 1;
    }
    if (ioctl(fd, VIRTGPU_WAIT, &wt)) {
        printf("virgl3d-fail draw-wait errno=%d\n", errno);
        return 1;
    }

    // Fullscreen triangle in pure green: every probe must now read it.
    printf("virgl3d: draw bgra=%02x%02x%02x%02x\n", px[0], px[1], px[2], px[3]);
    if (check_pixels(px, 0, 255, 0, 255, "draw"))
        return 1;

    // ── Phase 3: the same draw from a HOST3D blob vertex buffer ──
    uint64_t has_blob = 0, has_host_visible = 0;
    struct vg_getparam gb = { .param = PARAM_RESOURCE_BLOB,
                              .value = (uint64_t)(uintptr_t)&has_blob };
    struct vg_getparam gh = { .param = PARAM_HOST_VISIBLE,
                              .value = (uint64_t)(uintptr_t)&has_host_visible };
    if (ioctl(fd, VIRTGPU_GETPARAM, &gb) || ioctl(fd, VIRTGPU_GETPARAM, &gh) ||
        !has_blob || !has_host_visible) {
        printf("virgl3d: blob phase skipped (resource_blob=%u host_visible=%u)\n",
               (unsigned)has_blob, (unsigned)has_host_visible);
    } else {
        // virgl_drm_winsys_resource_create_blob: a page-sized MAPPABLE HOST3D
        // blob whose host object the embedded PIPE_RESOURCE_CREATE describes.
        const uint32_t blob_id = 1;
        uint32_t pc[12] = { 0 };
        pc[0] = VIRGL_CMD0(CCMD_PIPE_RESOURCE_CREATE, 0, 11);
        pc[1] = PIPE_BUFFER;                       // TARGET
        pc[2] = VIRGL_FORMAT_R8_UNORM;             // FORMAT
        pc[3] = PIPE_BIND_VERTEX_BUFFER;           // BIND
        pc[4] = 4096;                              // WIDTH (bytes)
        pc[5] = 1;                                 // HEIGHT
        pc[6] = 1;                                 // DEPTH
        pc[7] = 1;                                 // ARRAY_SIZE
        pc[8] = 0;                                 // LAST_LEVEL
        pc[9] = 0;                                 // NR_SAMPLES
        pc[10] = VIRGL_RESOURCE_FLAG_MAP_PERSISTENT; // FLAGS
        pc[11] = blob_id;                          // BLOB_ID
        struct vg_resource_create_blob bb = {
            .blob_mem = BLOB_MEM_HOST3D,
            .blob_flags = BLOB_FLAG_USE_MAPPABLE,
            .size = 4096,
            .cmd_size = sizeof(pc),
            .cmd = (uint64_t)(uintptr_t)pc,
            .blob_id = blob_id,
        };
        if (ioctl(fd, VIRTGPU_RESOURCE_CREATE_BLOB, &bb)) {
            printf("virgl3d-fail blob-create errno=%d\n", errno);
            return 1;
        }
        struct vg_map bm = { .handle = bb.bo_handle };
        if (ioctl(fd, VIRTGPU_MAP, &bm)) {
            printf("virgl3d-fail blob-map errno=%d\n", errno);
            return 1;
        }
        void *bp = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, bm.offset);
        if (bp == MAP_FAILED) {
            printf("virgl3d-fail blob-mmap errno=%d\n", errno);
            return 1;
        }
        const float bverts[12] = { -1, -1, 0, 1, 3, -1, 0, 1, -1, 3, 0, 1 };
        memcpy(bp, bverts, sizeof(bverts));

        // Clear to red first, so a dropped draw is visible as red.
        static uint32_t bc[64];
        unsigned k = 0;
        bc[k++] = VIRGL_CMD0(CCMD_CLEAR, 0, 8);
        bc[k++] = PIPE_CLEAR_COLOR0;
        bc[k++] = f2u(1.0f);
        bc[k++] = f2u(0.0f);
        bc[k++] = f2u(0.0f);
        bc[k++] = f2u(1.0f);
        bc[k++] = 0;
        bc[k++] = 0;
        bc[k++] = 0;
        bc[k++] = VIRGL_CMD0(CCMD_SET_VERTEX_BUFFERS, 0, 3);
        bc[k++] = 16;            // stride
        bc[k++] = 0;             // offset
        bc[k++] = bb.res_handle;
        // Shaders, vertex elements, blend/DSA/rasterizer, viewport and
        // framebuffer are context state from phase 2.
        bc[k++] = VIRGL_CMD0(CCMD_DRAW_VBO, 0, 12);
        bc[k++] = 0;
        bc[k++] = 3;
        bc[k++] = PIPE_PRIM_TRIANGLES;
        bc[k++] = 0;
        bc[k++] = 1;
        bc[k++] = 0;
        bc[k++] = 0;
        bc[k++] = 0;
        bc[k++] = 0;
        bc[k++] = 0;
        bc[k++] = 2;
        bc[k++] = 0;
        uint32_t bbos[2] = { rc.bo_handle, bb.bo_handle };
        struct vg_execbuffer eb3 = {
            .size = k * 4,
            .command = (uint64_t)(uintptr_t)bc,
            .bo_handles = (uint64_t)(uintptr_t)bbos,
            .num_bo_handles = 2,
            .fence_fd = -1,
        };
        if (ioctl(fd, VIRTGPU_EXECBUFFER, &eb3)) {
            printf("virgl3d-fail blob-draw-execbuffer errno=%d\n", errno);
            return 1;
        }
        if (ioctl(fd, VIRTGPU_TRANSFER_FROM_HOST, &tf)) {
            printf("virgl3d-fail blob-draw-transfer errno=%d\n", errno);
            return 1;
        }
        if (ioctl(fd, VIRTGPU_WAIT, &wt)) {
            printf("virgl3d-fail blob-draw-wait errno=%d\n", errno);
            return 1;
        }
        printf("virgl3d: blob draw bgra=%02x%02x%02x%02x\n", px[0], px[1], px[2], px[3]);
        if (check_pixels(px, 0, 255, 0, 255, "blob-draw"))
            return 1;
    }

    // The serial harness matches its expect token only when a newline
    // follows immediately, so the token line stays fixed and bare.
    printf("virgl3d-ok %ux%u\n", W, H);
    // Common terminal token for the always-on demo matrix: present on
    // success AND on a clean environment skip, absent on any failure.
    printf("virgl3d-done\n");
    return 0;
}
