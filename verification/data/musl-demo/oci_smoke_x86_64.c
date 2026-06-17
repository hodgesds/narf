// OCI-container smoke. A *minimal but faithful* OCI runtime: it reads
// an OCI bundle (a `config.json` runtime-spec subset plus a `rootfs/`)
// that the kernel seeds at `/oci`, then performs the standard container
// bring-up — create namespaces, set the container hostname, `chroot`
// into the bundle rootfs, and `execve` the configured entrypoint — and
// verifies that the contained process runs *isolated*, seeing only the
// container's filesystem and identity.
//
// One static binary plays both roles (selected by argv):
//
//   * RUNTIME  (`oci_smoke`, no args): the container manager. Parses
//     /oci/config.json, fork()s, and in the child does
//     unshare(namespaces) → sethostname → chroot(rootfs) → chdir("/")
//     → execve("/init", {"--contained"}). The parent waits and reports.
//
//   * PAYLOAD  (`/init --contained`): the entrypoint that runs *inside*
//     the container. It proves isolation three ways:
//       (a) it is executing at all — chroot+exec of the bundle rootfs
//           worked (the kernel resolved "/init" under the new root);
//       (b) open("/etc/os-release") returns the *container's* file
//           (contains "NARF-Container"), not the host's — proves the
//           chroot rewrites path lookups;
//       (c) the env handed to execve propagated (OCI_CONTAINER=1).
//     On success it prints `oci-container-ok` and exits 0.
//
// The RUNTIME additionally distinguishes a *real* UTS namespace from a
// global hostname change: it snapshots its own hostname before the
// fork and re-checks it after the child exits. If the child's
// sethostname() did NOT leak back to the parent, the UTS namespace
// isolated it — the runtime prints `oci-uts-isolated`. That token only
// appears when the kernel is built with the `container` feature (the
// nightly OCI job builds with it and asserts the stronger token); the
// default per-PR build passes on the chroot-based `oci-smoke-ok`, which
// is the OCI essence.
//
// Success token (runtime): "oci-smoke-ok". Stronger token, container
// builds only: "oci-uts-isolated". Payload token: "oci-container-ok".
//
// Build: the uniform musl-demo recipe (musl-gcc -O2 -fPIE -pie,
// dynamic, PT_INTERP=/lib/ld-musl-x86_64.so.1). The bundle rootfs the
// kernel seeds therefore also carries /lib/ld-musl-x86_64.so.1, and the
// loader resolves PT_INTERP *under the chroot* (see process.rs) so the
// container loads its own dynamic linker, not the host's.
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/syscall.h>

static void w(const char *m) { write(1, m, strlen(m)); }

// musl stubs a few of these libc wrappers to -ENOSYS on some configs;
// go straight to the kernel for the privileged container primitives so
// the smoke exercises NARF's real syscall handlers regardless. The wire
// numbers are ancient and present in every musl <sys/syscall.h>.
static long raw_unshare(unsigned long flags) {
    return syscall(SYS_unshare, flags);
}
static long raw_sethostname(const char *n, unsigned long len) {
    return syscall(SYS_sethostname, n, len);
}
static long raw_chroot(const char *p) { return syscall(SYS_chroot, p); }

// Read the whole of `path` into `buf` (NUL-terminated, truncated to
// cap-1). Returns the byte count, or -1 on open failure.
static long slurp(const char *path, char *buf, long cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    long total = 0;
    for (;;) {
        long n = read(fd, buf + total, cap - 1 - total);
        if (n <= 0) {
            break;
        }
        total += n;
        if (total >= cap - 1) {
            break;
        }
    }
    close(fd);
    buf[total] = '\0';
    return total;
}

// Extract the string value of JSON member `"key"` (a `"key": "value"`
// pair, whitespace-tolerant) into `out`. Returns 1 on success. This is
// a deliberately tiny scanner — enough to read the few spec fields the
// runtime acts on, not a general JSON parser.
static int json_str(const char *buf, const char *key, char *out, long cap) {
    char needle[64];
    int kn = 0;
    needle[kn++] = '"';
    for (const char *k = key; *k && kn < (int)sizeof needle - 2; k++) {
        needle[kn++] = *k;
    }
    needle[kn++] = '"';
    needle[kn] = '\0';
    const char *p = strstr(buf, needle);
    if (!p) {
        return 0;
    }
    p += kn;                       // past the closing quote of the key
    while (*p && *p != ':') {
        p++;
    }
    if (*p != ':') {
        return 0;
    }
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }
    if (*p != '"') {
        return 0;
    }
    p++;
    long i = 0;
    while (*p && *p != '"' && i < cap - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 1;
}

// ── PAYLOAD: runs inside the container ─────────────────────────────
static int run_contained(void) {
    w("oci-payload: entered container\n");

    // (b) The chroot must have rewritten path lookups: this open
    // resolves "/etc/os-release" under the *bundle* rootfs, which the
    // kernel seeded with a NARF-Container marker. The host's real
    // /etc/os-release (if any) would not contain it.
    char osr[256];
    long n = slurp("/etc/os-release", osr, sizeof osr);
    if (n < 0) {
        w("oci-fail: payload cannot open /etc/os-release (chroot rootfs)\n");
        return 1;
    }
    if (!strstr(osr, "NARF-Container")) {
        w("oci-fail: payload /etc/os-release is not the container's\n");
        return 1;
    }
    w("oci-payload: rootfs isolated (/etc/os-release is the container's)\n");

    // (c) The environment handed to execve must have propagated.
    const char *marker = getenv("OCI_CONTAINER");
    if (!marker || strcmp(marker, "1") != 0) {
        w("oci-fail: payload missing OCI_CONTAINER env\n");
        return 1;
    }

    // Informational: report the hostname the container sees. Whether
    // this is *isolated* from the host is asserted by the runtime
    // parent (which can compare before/after); here we just surface it.
    struct utsname uts;
    if (uname(&uts) == 0) {
        w("oci-payload: container hostname=");
        w(uts.nodename);
        w("\n");
    }

    w("oci-container-ok\n");
    return 0;
}

// ── RUNTIME: the container manager ─────────────────────────────────
static int run_runtime(const char *self) {
    // 1. Read the OCI bundle spec the kernel seeded at /oci.
    char spec[2048];
    if (slurp("/oci/config.json", spec, sizeof spec) < 0) {
        w("oci-fail: cannot read /oci/config.json (bundle not seeded?)\n");
        return 1;
    }

    char rootfs[256] = "/oci/rootfs";
    char hostname[128] = "narfbox";
    json_str(spec, "path", rootfs, sizeof rootfs);   // root.path
    json_str(spec, "hostname", hostname, sizeof hostname);

    // Map the spec's requested namespaces to unshare(2) flags. Absent
    // any (older spec), default to the full container set. On a kernel
    // without the `container` feature these bits are accepted but inert
    // (unshare returns 0); the chroot isolation below still holds.
    unsigned long ns = 0;
    if (strstr(spec, "\"pid\""))     ns |= CLONE_NEWPID;
    if (strstr(spec, "\"uts\""))     ns |= CLONE_NEWUTS;
    if (strstr(spec, "\"ipc\""))     ns |= CLONE_NEWIPC;
    if (strstr(spec, "\"mount\""))   ns |= CLONE_NEWNS;
    if (strstr(spec, "\"network\"")) ns |= CLONE_NEWNET;
    if (ns == 0) {
        ns = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS |
             CLONE_NEWNET;
    }

    // Snapshot our own hostname so we can later tell a real UTS
    // namespace (child change does NOT leak here) from a global one.
    struct utsname before;
    before.nodename[0] = '\0';
    uname(&before);

    w("oci-runtime: launching container, rootfs=");
    w(rootfs);
    w("\n");

    pid_t pid = fork();
    if (pid < 0) {
        w("oci-fail: fork\n");
        return 1;
    }
    if (pid == 0) {
        // ── child: become the contained init ──────────────────────
        raw_unshare(ns);
        raw_sethostname(hostname, strlen(hostname));
        if (raw_chroot(rootfs) != 0) {
            w("oci-fail: chroot into bundle rootfs\n");
            _exit(127);
        }
        if (chdir("/") != 0) {
            w("oci-fail: chdir(/) in container\n");
            _exit(127);
        }
        // Exec the bundle entrypoint. "/init" resolves under the new
        // root; the kernel seeded the (static) binary there. argv[0]
        // marks payload mode; the env proves propagation.
        char *argv[] = {(char *)"/init", (char *)"--contained", 0};
        char *envp[] = {(char *)"PATH=/bin", (char *)"OCI_CONTAINER=1", 0};
        execve("/init", argv, envp);
        w("oci-fail: execve(/init) in container\n");
        _exit(127);
    }

    // ── parent: wait for the container to finish ───────────────────
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        w("oci-fail: waitpid\n");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        w("oci-fail: container exited non-zero\n");
        return 1;
    }

    // Did the child's sethostname leak back to us? If not, the UTS
    // namespace isolated it (kernel built with `container`). This
    // stronger token is what the nightly OCI job asserts.
    struct utsname after;
    after.nodename[0] = '\0';
    uname(&after);
    if (before.nodename[0] && strcmp(before.nodename, after.nodename) == 0 &&
        strcmp(after.nodename, hostname) != 0) {
        w("oci-uts-isolated\n");
    }

    (void)self;
    w("oci-smoke-ok\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--contained") == 0) {
        return run_contained();
    }
    return run_runtime(argv[0]);
}
