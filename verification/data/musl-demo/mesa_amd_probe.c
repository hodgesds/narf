// Mesa AMD driver probe for NARF (Navi22 milestone 9).
//
// One binary, four subcommands, each printing grep-able `MESAPROBE` lines.
// It is the payload of /mesa-amd-smoke.sh in the image REGEN_amd_gl_rootfs.sh
// builds, and the first thing to run on bare metal:
//
//   mesa_amd_probe libs  dlopen libgallium (radeonsi + the amdgpu winsys) and
//                        the RADV ICD with RTLD_NOW and resolve entry points —
//                        the built driver LOADS, independent of any device.
//   mesa_amd_probe drm   enumerate /dev/dri/{card,renderD}* through libdrm and
//                        run libdrm_amdgpu's amdgpu_device_initialize on each
//                        node; on an amdgpu node also query identity and the
//                        GFX IP. On a non-amdgpu node the expected answer is
//                        a clean error (libdrm rejects DRM major != 3).
//   mesa_amd_probe vk    create a Vulkan instance through the loader (honours
//                        VK_DRIVER_FILES, so the smoke can restrict it to the
//                        RADV ICD) and list physical devices + driver IDs.
//   mesa_amd_probe egl   EGL on every DRM node twice — EGL_EXT_platform_device
//                        and the GBM platform a KMS compositor uses — then a
//                        GLES2 triangle into a 64x64 FBO with pixel readback.
//                        The renderer string says which driver Mesa picked.
//
// Exit status: 0 when every step either worked or failed the way a missing
// device should (an error code, never a signal); 1 when something that must
// work regardless of hardware did not (a library that will not load, an
// instance that cannot be created, a context that renders wrong pixels).
#define _GNU_SOURCE 1
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <xf86drm.h>
#include <amdgpu.h>
#include <amdgpu_drm.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <gbm.h>
#include <vulkan/vulkan.h>

#define P(...) printf("MESAPROBE " __VA_ARGS__)

#ifndef NARF_MESA_VER
#define NARF_MESA_VER "26.2.4"
#endif

static const char *classify(const char *renderer)
{
    if (!renderer)
        return "none";
    if (strstr(renderer, "llvmpipe"))
        return "llvmpipe";
    if (strstr(renderer, "softpipe"))
        return "softpipe";
    if (strstr(renderer, "virgl") || strstr(renderer, "Virgl"))
        return "virgl";
    if (strstr(renderer, "AMD") || strstr(renderer, "radeonsi") || strstr(renderer, "Radeon"))
        return "amd";
    return "other";
}

// ------------------------------------------------------------------ libs ---
static int cmd_libs(void)
{
    int bad = 0;
    // Mesa >= 24.3 links every gallium driver into libgallium-<ver>.so; the
    // EGL/GBM/GLX loaders call into it directly and the per-driver
    // /usr/lib/dri/radeonsi_dri.so is only a symlink to the libdril_dri.so
    // stub kept for external DRI loaders (Xorg). radeonsi itself has no
    // exported symbol; the amdgpu winsys it sits on does.
    const char *gallium = "/usr/lib/libgallium-" NARF_MESA_VER ".so";
    void *h = dlopen(gallium, RTLD_NOW | RTLD_LOCAL);
    P("libs path=%s dlopen=%s%s%s\n", gallium, h ? "ok" : "fail", h ? "" : " err=", h ? "" : dlerror());
    if (h) {
        static const char *const syms[] = { "amdgpu_winsys_create", "driCreateNewScreen3", NULL };
        for (int i = 0; syms[i]; i++) {
            void *s = dlsym(h, syms[i]);
            P("libs path=%s sym=%s %s\n", gallium, syms[i], s ? "found" : "missing");
            if (!s)
                bad = 1;
        }
        dlclose(h);
    } else {
        bad = 1;
    }
    P("libs path=/usr/lib/dri/radeonsi_dri.so present=%d\n", access("/usr/lib/dri/radeonsi_dri.so", F_OK) == 0);
    void *v = dlopen("/usr/lib/libvulkan_radeon.so", RTLD_NOW | RTLD_LOCAL);
    P("libs path=/usr/lib/libvulkan_radeon.so dlopen=%s%s%s\n", v ? "ok" : "fail", v ? "" : " err=",
      v ? "" : dlerror());
    if (v) {
        void *gipa = dlsym(v, "vk_icdGetInstanceProcAddr");
        P("libs path=/usr/lib/libvulkan_radeon.so sym=vk_icdGetInstanceProcAddr %s\n", gipa ? "found" : "missing");
        if (!gipa)
            bad = 1;
        dlclose(v);
    } else {
        bad = 1;
    }
    P("libs result=%s\n", bad ? "FAIL" : "ok");
    return bad;
}

// ------------------------------------------------------------------- drm ---
static int dri_nodes(char paths[][64], int max)
{
    int n = 0;
    DIR *d = opendir("/dev/dri");
    if (!d) {
        P("drm opendir=/dev/dri errno=%d\n", errno);
        return 0;
    }
    struct dirent *e;
    while ((e = readdir(d)) && n < max) {
        if (strncmp(e->d_name, "card", 4) && strncmp(e->d_name, "renderD", 7))
            continue;
        snprintf(paths[n++], 64, "/dev/dri/%s", e->d_name);
    }
    closedir(d);
    // Stable order: cards first, then render nodes, each ascending.
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (strcmp(paths[j], paths[i]) < 0) {
                char t[64];
                memcpy(t, paths[i], 64);
                memcpy(paths[i], paths[j], 64);
                memcpy(paths[j], t, 64);
            }
    return n;
}

static void amdgpu_details(amdgpu_device_handle dev)
{
    struct amdgpu_gpu_info gi;
    memset(&gi, 0, sizeof(gi));
    int r = amdgpu_query_gpu_info(dev, &gi);
    const char *mk = amdgpu_get_marketing_name(dev);
    P("drm   amdgpu marketing=\"%s\" query_gpu_info rc=%d asic=0x%x chip_rev=0x%x ext_rev=0x%x family=%u\n",
      mk ? mk : "(null)", r, gi.asic_id, gi.chip_rev, gi.chip_external_rev, gi.family_id);
    struct drm_amdgpu_info_hw_ip ip;
    memset(&ip, 0, sizeof(ip));
    r = amdgpu_query_hw_ip_info(dev, AMDGPU_HW_IP_GFX, 0, &ip);
    P("drm   amdgpu hw_ip_info(GFX) rc=%d ver=%u.%u rings=0x%x discovery=0x%06x\n", r, ip.hw_ip_version_major,
      ip.hw_ip_version_minor, ip.available_rings, ip.ip_discovery_version);
    uint32_t accel = 0;
    r = amdgpu_query_info(dev, AMDGPU_INFO_ACCEL_WORKING, sizeof(accel), &accel);
    P("drm   amdgpu accel_working rc=%d val=%u\n", r, accel);
}

static int cmd_drm(void)
{
    char paths[32][64];
    int n = dri_nodes(paths, 32), amd = 0;
    P("drm nodes=%d\n", n);

    drmDevicePtr devs[16];
    int nd = drmGetDevices2(0, devs, 16);
    P("drm drmGetDevices2=%d\n", nd);
    for (int i = 0; i < nd; i++) {
        drmDevicePtr d = devs[i];
        P("drm  device[%d] bustype=%d nodes=0x%x", i, d->bustype, d->available_nodes);
        if (d->bustype == DRM_BUS_PCI && d->deviceinfo.pci)
            printf(" pci=%04x:%04x rev=%02x", d->deviceinfo.pci->vendor_id, d->deviceinfo.pci->device_id,
                   d->deviceinfo.pci->revision_id);
        printf("\n");
    }
    if (nd > 0)
        drmFreeDevices(devs, nd);

    for (int i = 0; i < n; i++) {
        int fd = open(paths[i], O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            P("drm node=%s open errno=%d\n", paths[i], errno);
            continue;
        }
        drmVersionPtr v = drmGetVersion(fd);
        if (!v) {
            // libdrm_amdgpu would dereference this NULL itself; stop here.
            P("drm node=%s version=FAIL errno=%d (amdgpu_device_initialize skipped)\n", paths[i], errno);
            close(fd);
            continue;
        }
        P("drm node=%s type=%d driver=%s version=%d.%d.%d\n", paths[i], drmGetNodeTypeFromFd(fd), v->name,
          v->version_major, v->version_minor, v->version_patchlevel);
        int is_amd = strcmp(v->name, "amdgpu") == 0;
        drmFreeVersion(v);

        uint32_t maj = 0, min = 0;
        amdgpu_device_handle dev = NULL;
        int r = amdgpu_device_initialize(fd, &maj, &min, &dev);
        P("drm node=%s amdgpu_device_initialize=%d (%s) drm=%u.%u%s\n", paths[i], r, r ? strerror(-r) : "ok",
          maj, min, is_amd ? "" : " expected-failure=non-amdgpu");
        if (r == 0) {
            amd++;
            amdgpu_details(dev);
            amdgpu_device_deinitialize(dev);
        }
        close(fd);
    }
    P("drm result amdgpu_nodes=%d\n", amd);
    return 0;
}

// -------------------------------------------------------------------- vk ---
static const char *driver_id_name(VkDriverId id)
{
    switch (id) {
    case VK_DRIVER_ID_MESA_RADV: return "RADV";
    case VK_DRIVER_ID_MESA_LLVMPIPE: return "lavapipe";
    case VK_DRIVER_ID_MESA_VENUS: return "venus";
    default: return "other";
    }
}

static int cmd_vk(void)
{
    const char *files = getenv("VK_DRIVER_FILES");
    if (!files)
        files = getenv("VK_ICD_FILENAMES");
    P("vk driver_files=%s\n", files ? files : "(loader default)");
    VkApplicationInfo app = {
        .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "mesa_amd_probe",
        .apiVersion = VK_API_VERSION_1_3,
    };
    VkInstanceCreateInfo ci = { .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, .pApplicationInfo = &app };
    VkInstance inst;
    VkResult r = vkCreateInstance(&ci, NULL, &inst);
    P("vk vkCreateInstance=%d\n", r);
    if (r != VK_SUCCESS) {
        P("vk result=FAIL\n");
        return 1;
    }
    uint32_t n = 0;
    r = vkEnumeratePhysicalDevices(inst, &n, NULL);
    P("vk vkEnumeratePhysicalDevices=%d devices=%u\n", r, n);
    VkPhysicalDevice pd[8];
    if (n > 8)
        n = 8;
    if (n)
        vkEnumeratePhysicalDevices(inst, &n, pd);
    for (uint32_t i = 0; i < n; i++) {
        VkPhysicalDeviceDriverProperties drv = { .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES };
        VkPhysicalDeviceProperties2 p2 = { .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2, .pNext = &drv };
        vkGetPhysicalDeviceProperties2(pd[i], &p2);
        P("vk  device[%u] name=\"%s\" vendor=0x%x device=0x%x type=%d driver=%s info=\"%s\"\n", i,
          p2.properties.deviceName, p2.properties.vendorID, p2.properties.deviceID, p2.properties.deviceType,
          driver_id_name(drv.driverID), drv.driverInfo);
    }
    vkDestroyInstance(inst, NULL);
    P("vk result=ok devices=%u\n", n);
    return 0;
}

// ------------------------------------------------------------------- egl ---
static GLuint compile(GLenum type, const char *src)
{
    GLuint s = glCreateShader(type);
    glShaderSource(s, 1, &src, NULL);
    glCompileShader(s);
    GLint ok = 0;
    glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
    if (!ok) {
        char log[256] = { 0 };
        glGetShaderInfoLog(s, sizeof(log) - 1, NULL, log);
        P("egl   shader compile failed: %s\n", log);
    }
    return s;
}

// Draw one red triangle covering the centre of a 64x64 FBO cleared blue,
// read back the centre and a corner. Returns 0 when both pixels are right.
static int triangle(void)
{
    GLuint rb, fb;
    glGenRenderbuffers(1, &rb);
    glBindRenderbuffer(GL_RENDERBUFFER, rb);
    glRenderbufferStorage(GL_RENDERBUFFER, GL_RGBA4, 64, 64);
    glGenFramebuffers(1, &fb);
    glBindFramebuffer(GL_FRAMEBUFFER, fb);
    glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_RENDERBUFFER, rb);
    if (glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE) {
        P("egl   tri fbo=incomplete\n");
        return 1;
    }
    GLuint prog = glCreateProgram();
    glAttachShader(prog, compile(GL_VERTEX_SHADER, "attribute vec2 p; void main(){gl_Position=vec4(p,0.0,1.0);}"));
    glAttachShader(prog, compile(GL_FRAGMENT_SHADER,
                                 "precision mediump float; void main(){gl_FragColor=vec4(1.0,0.0,0.0,1.0);}"));
    glBindAttribLocation(prog, 0, "p");
    glLinkProgram(prog);
    GLint linked = 0;
    glGetProgramiv(prog, GL_LINK_STATUS, &linked);
    if (!linked) {
        P("egl   tri link=fail\n");
        return 1;
    }
    static const GLfloat v[] = { -0.8f, -0.8f, 0.8f, -0.8f, 0.0f, 0.8f };
    glViewport(0, 0, 64, 64);
    glClearColor(0.0f, 0.0f, 1.0f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    glUseProgram(prog);
    glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, v);
    glEnableVertexAttribArray(0);
    glDrawArrays(GL_TRIANGLES, 0, 3);
    uint8_t c[4] = { 0 }, k[4] = { 0 };
    glReadPixels(32, 32, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, c);
    glReadPixels(1, 62, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, k);
    GLenum err = glGetError();
    int ok = err == GL_NO_ERROR && c[0] > 200 && c[1] < 50 && c[2] < 50 && k[0] < 50 && k[2] > 200;
    P("egl   tri centre=%02x%02x%02x corner=%02x%02x%02x glerr=0x%x %s\n", c[0], c[1], c[2], k[0], k[1], k[2], err,
      ok ? "ok" : "WRONG");
    glDeleteProgram(prog);
    glDeleteFramebuffers(1, &fb);
    glDeleteRenderbuffers(1, &rb);
    return ok ? 0 : 1;
}

// Initialise `dpy`, make a surfaceless GLES2 context current, report the
// renderer and draw. Returns 1 only for wrong rendering; an EGL init that
// fails is reported and returns 0 (that is what a missing device does).
static int egl_session(const char *label, EGLDisplay dpy)
{
    if (dpy == EGL_NO_DISPLAY) {
        P("egl %s display=none err=0x%x\n", label, eglGetError());
        return 0;
    }
    EGLint maj = 0, min = 0;
    if (!eglInitialize(dpy, &maj, &min)) {
        P("egl %s eglInitialize=fail err=0x%x\n", label, eglGetError());
        return 0;
    }
    eglBindAPI(EGL_OPENGL_ES_API);
    static const EGLint attrs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
    EGLContext ctx = eglCreateContext(dpy, EGL_NO_CONFIG_KHR, EGL_NO_CONTEXT, attrs);
    if (ctx == EGL_NO_CONTEXT || !eglMakeCurrent(dpy, EGL_NO_SURFACE, EGL_NO_SURFACE, ctx)) {
        P("egl %s egl=%d.%d context=fail err=0x%x\n", label, maj, min, eglGetError());
        if (ctx != EGL_NO_CONTEXT)
            eglDestroyContext(dpy, ctx);
        eglTerminate(dpy);
        return 0;
    }
    const char *r = (const char *)glGetString(GL_RENDERER);
    P("egl %s egl=%d.%d vendor=\"%s\" renderer=\"%s\" class=%s gl=\"%s\"\n", label, maj, min,
      (const char *)glGetString(GL_VENDOR), r ? r : "(null)", classify(r), (const char *)glGetString(GL_VERSION));
    int bad = triangle();
    eglMakeCurrent(dpy, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglDestroyContext(dpy, ctx);
    eglTerminate(dpy);
    return bad;
}

static int cmd_egl(void)
{
    int bad = 0;
    const char *ov = getenv("MESA_LOADER_DRIVER_OVERRIDE");
    P("egl override=%s software=%s\n", ov ? ov : "(none)",
      getenv("LIBGL_ALWAYS_SOFTWARE") ? getenv("LIBGL_ALWAYS_SOFTWARE") : "(unset)");

    PFNEGLQUERYDEVICESEXTPROC query_devices = (void *)eglGetProcAddress("eglQueryDevicesEXT");
    PFNEGLQUERYDEVICESTRINGEXTPROC query_string = (void *)eglGetProcAddress("eglQueryDeviceStringEXT");
    PFNEGLGETPLATFORMDISPLAYEXTPROC get_platform = (void *)eglGetProcAddress("eglGetPlatformDisplayEXT");
    if (query_devices && query_string && get_platform) {
        EGLDeviceEXT devs[16];
        EGLint nd = 0;
        if (!query_devices(16, devs, &nd))
            nd = 0;
        P("egl devices=%d\n", nd);
        for (EGLint i = 0; i < nd; i++) {
            const char *ext = query_string(devs[i], EGL_EXTENSIONS);
            const char *card = ext && strstr(ext, "EGL_EXT_device_drm") ? query_string(devs[i], EGL_DRM_DEVICE_FILE_EXT)
                                                                         : NULL;
            const char *render = ext && strstr(ext, "EGL_EXT_device_drm_render_node")
                                     ? query_string(devs[i], EGL_DRM_RENDER_NODE_FILE_EXT)
                                     : NULL;
            char label[160];
            snprintf(label, sizeof(label), "device[%d] card=%s render=%s", i, card ? card : "-",
                     render ? render : "-");
            bad |= egl_session(label, get_platform(EGL_PLATFORM_DEVICE_EXT, devs[i], NULL));
        }
    } else {
        P("egl EGL_EXT_device_enumeration=missing\n");
    }

    // The compositor path: GBM on each DRM node. Mesa's loader picks the
    // driver from the kernel driver name (amdgpu -> radeonsi) and, when the
    // hardware screen cannot be created, eglInitialize retries in software.
    char paths[32][64];
    int n = dri_nodes(paths, 32);
    for (int i = 0; i < n; i++) {
        int fd = open(paths[i], O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            P("egl gbm node=%s open errno=%d\n", paths[i], errno);
            continue;
        }
        struct gbm_device *g = gbm_create_device(fd);
        if (!g) {
            P("egl gbm node=%s gbm_create_device=fail\n", paths[i]);
            close(fd);
            continue;
        }
        char label[96];
        snprintf(label, sizeof(label), "gbm node=%s backend=%s", paths[i], gbm_device_get_backend_name(g));
        bad |= egl_session(label, get_platform ? get_platform(EGL_PLATFORM_GBM_KHR, g, NULL) : EGL_NO_DISPLAY);
        gbm_device_destroy(g);
        close(fd);
    }
    P("egl result=%s\n", bad ? "FAIL" : "ok");
    return bad;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2) {
        fprintf(stderr, "usage: %s libs|drm|vk|egl\n", argv[0]);
        return 2;
    }
    if (!strcmp(argv[1], "libs"))
        return cmd_libs();
    if (!strcmp(argv[1], "drm"))
        return cmd_drm();
    if (!strcmp(argv[1], "vk"))
        return cmd_vk();
    if (!strcmp(argv[1], "egl"))
        return cmd_egl();
    fprintf(stderr, "unknown subcommand %s\n", argv[1]);
    return 2;
}
