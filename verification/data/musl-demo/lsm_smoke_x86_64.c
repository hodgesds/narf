// LSM self-attr smoke: the Linux 6.8 generic LSM syscalls. Confirm
// lsm_list_modules reports NARF's active modules (capability + Landlock),
// including the too-small-buffer E2BIG path; lsm_get_self_attr reports zero
// context attributes (NARF has no MAC label); lsm_set_self_attr is
// unsupported (EOPNOTSUPP). Issued raw (no musl wrappers). Token "lsm-ok".
//
// Build: see REGEN_lsm_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/syscall.h>

#ifndef SYS_lsm_get_self_attr
#define SYS_lsm_get_self_attr 459
#endif
#ifndef SYS_lsm_set_self_attr
#define SYS_lsm_set_self_attr 460
#endif
#ifndef SYS_lsm_list_modules
#define SYS_lsm_list_modules 461
#endif

#define LSM_ID_LANDLOCK 110
#define LSM_ATTR_CURRENT 2

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    // ── lsm_list_modules: list NARF's active LSMs ──
    uint64_t ids[8];
    size_t sz = sizeof ids;
    long n = syscall(SYS_lsm_list_modules, ids, &sz, 0L);
    if (n < 1) { w("lsm-fail: list\n"); return 1; }
    if (sz != (size_t)n * sizeof(uint64_t)) { w("lsm-fail: list-size\n"); return 1; }
    int saw_landlock = 0;
    for (long i = 0; i < n; i++) {
        if (ids[i] == LSM_ID_LANDLOCK) saw_landlock = 1;
    }
    if (!saw_landlock) { w("lsm-fail: no-landlock\n"); return 1; }

    // ── too-small buffer reports E2BIG and the required size ──
    size_t small = 0;
    if (syscall(SYS_lsm_list_modules, ids, &small, 0L) != -1 || errno != E2BIG) {
        w("lsm-fail: e2big\n"); return 1;
    }
    if (small != (size_t)n * sizeof(uint64_t)) { w("lsm-fail: e2big-size\n"); return 1; }

    // ── lsm_get_self_attr: NARF exposes no context, so zero attributes ──
    char buf[256];
    size_t gsz = sizeof buf;
    long g = syscall(SYS_lsm_get_self_attr, (long)LSM_ATTR_CURRENT, buf, &gsz, 0L);
    if (g != 0) { w("lsm-fail: get\n"); return 1; }

    // ── lsm_set_self_attr: unsupported (no settable MAC context) ──
    if (syscall(SYS_lsm_set_self_attr, (long)LSM_ATTR_CURRENT, buf, (long)sizeof buf, 0L) != -1
        || errno != EOPNOTSUPP) {
        w("lsm-fail: set\n"); return 1;
    }

    w("lsm-ok\n");
    return 0;
}
