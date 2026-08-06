// Report what libdrm ACTUALLY sees for NARF's DRM nodes.
//
// Mesa's `loader_is_device_render_capable()` is nothing but a drmGetDevice2()
// plus a test of `available_nodes & (1 << DRM_NODE_RENDER)`; when that bit is
// clear, `dri2_initialize_drm()` bails with "DRI2: failed to get compatible
// render device" and kwin gets no EGL. Every previous attempt at this bug
// inferred what libdrm wanted from NARF's sysfs and shipped a guess — six in
// a row, all wrong. This calls the real function in the guest's own libdrm
// and prints the bit, so there is nothing left to infer.
//
// Built on the host, run in the guest: links only against libdrm.so.2 +
// libc, both of which the Fedora rootfs already ships for kwin's sake.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <xf86drm.h>

static void dump_nodes(const char *label, drmDevicePtr d)
{
    printf("DRMC: %s available_nodes=0x%x%s%s%s\n", label, d->available_nodes,
           (d->available_nodes & (1 << DRM_NODE_PRIMARY)) ? " PRIMARY" : "",
           (d->available_nodes & (1 << DRM_NODE_CONTROL)) ? " CONTROL" : "",
           (d->available_nodes & (1 << DRM_NODE_RENDER)) ? " RENDER" : "");
    for (int i = 0; i < DRM_NODE_MAX; i++)
        if (d->available_nodes & (1 << i))
            printf("DRMC: %s   node[%d]=%s\n", label, i, d->nodes[i]);
    printf("DRMC: %s bustype=%d\n", label, d->bustype);
    if (d->bustype == DRM_BUS_PCI && d->businfo.pci)
        printf("DRMC: %s pci=%04x:%02x:%02x.%u\n", label,
               d->businfo.pci->domain, d->businfo.pci->bus,
               d->businfo.pci->dev, d->businfo.pci->func);
    if (d->bustype == DRM_BUS_PCI && d->deviceinfo.pci)
        printf("DRMC: %s ids=%04x:%04x sub=%04x:%04x rev=%02x\n", label,
               d->deviceinfo.pci->vendor_id, d->deviceinfo.pci->device_id,
               d->deviceinfo.pci->subvendor_id, d->deviceinfo.pci->subdevice_id,
               d->deviceinfo.pci->revision_id);
}

// The exact per-node predicates `process_device()` applies. A node failing
// either is dropped from enumeration entirely and silently, which is what
// makes this bug invisible from the card node's point of view.
static void probe_one(const char *path)
{
    struct stat sb;
    printf("DRMC: === %s ===\n", path);
    if (stat(path, &sb)) {
        printf("DRMC: %s stat FAILED\n", path);
        return;
    }
    int maj = major(sb.st_rdev), min = minor(sb.st_rdev);
    printf("DRMC: %s rdev=%d:%d ischr=%d\n", path, maj, min, S_ISCHR(sb.st_mode));

    char p[256], buf[256];
    // drmNodeIsDRM()
    snprintf(p, sizeof p, "/sys/dev/char/%d:%d/device/drm", maj, min);
    printf("DRMC: %s drmNodeIsDRM(stat %s)=%d\n", path, p, stat(p, &sb) == 0);
    // drmParseSubsystemType()
    snprintf(p, sizeof p, "/sys/dev/char/%d:%d/device", maj, min);
    ssize_t n = readlink(p, buf, sizeof buf - 1);
    if (n < 0)
        printf("DRMC: %s readlink(%s) FAILED\n", path, p);
    else {
        buf[n] = 0;
        printf("DRMC: %s device -> %s\n", path, buf);
    }
    snprintf(p, sizeof p, "/sys/dev/char/%d:%d/device/subsystem", maj, min);
    n = readlink(p, buf, sizeof buf - 1);
    if (n < 0)
        printf("DRMC: %s readlink(%s) FAILED\n", path, p);
    else {
        buf[n] = 0;
        printf("DRMC: %s subsystem -> %s\n", path, buf);
    }

    // O_RDWR|O_CLOEXEC is exactly what kwin's NoopSession::openRestricted()
    // does. Print errno on failure: "open=-1" alone cannot distinguish a
    // permission problem from EBUSY from ENOENT, and those imply completely
    // different fixes.
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("DRMC: %s open=-1 errno=%d (%s)\n", path, errno, strerror(errno));
        return;
    }
    printf("DRMC: %s open=%d\n", path, fd);

    drmDevicePtr d = NULL;
    int r = drmGetDevice2(fd, 0, &d);
    printf("DRMC: %s drmGetDevice2=%d\n", path, r);
    if (r == 0 && d) {
        dump_nodes(path, d);
        // This single expression IS Mesa's render-capable test.
        printf("DRMC: %s RENDER_CAPABLE=%d\n", path,
               (d->available_nodes & (1 << DRM_NODE_RENDER)) ? 1 : 0);
        drmFreeDevice(&d);
    }
    close(fd);
}

int main(void)
{
    printf("DRMC: probe start\n");

    // What libdrm's own enumeration sees, independent of any single fd.
    drmDevicePtr devs[8];
    int n = drmGetDevices2(0, devs, 8);
    printf("DRMC: drmGetDevices2 count=%d\n", n);
    for (int i = 0; i < n; i++) {
        char lbl[32];
        snprintf(lbl, sizeof lbl, "dev[%d]", i);
        dump_nodes(lbl, devs[i]);
    }
    if (n > 0)
        drmFreeDevices(devs, n);

    probe_one("/dev/dri/card0");
    probe_one("/dev/dri/renderD128");

    printf("DRMC: probe done\n");
    return 0;
}
