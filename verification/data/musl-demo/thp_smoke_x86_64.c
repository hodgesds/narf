// systemd-tmpfiles' `w!` lines for the THP sysfs knobs (CachyOS thp.conf,
// thp-shrinker.conf):
//
//   w! /sys/kernel/mm/transparent_hugepage/defrag - - - - defer+madvise
//   w! /sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none - - - - 409
//
// On NARF both were read-only ("Failed to write file ...: Read-only file
// system"). On Linux they are root-writable attributes (mm/huge_memory.c
// defrag_store / enabled_store, mm/khugepaged.c max_ptes_none_store) that
// accept a fixed vocabulary and answer EINVAL for anything else.
//
// Needs root (writes /sys). Restores the values it found. Success token
// "thp-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define THP "/sys/kernel/mm/transparent_hugepage/"

static int failures;

static int put(const char *name, const char *value) {
    char path[256];
    snprintf(path, sizeof path, THP "%s", name);
    int fd = open(path, O_WRONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0)
        return -errno;
    ssize_t n = write(fd, value, strlen(value));
    int e = errno;
    close(fd);
    return n == (ssize_t)strlen(value) ? 0 : -e;
}

static void get(const char *name, char *out, size_t len) {
    char path[256];
    snprintf(path, sizeof path, THP "%s", name);
    out[0] = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    ssize_t n = read(fd, out, len - 1);
    close(fd);
    out[n > 0 ? n : 0] = 0;
}

static void check(const char *step, int got, int want) {
    if (got != want) {
        printf("thp-fail: %s: got %d (%s), want %d\n", step, got, strerror(-got), want);
        failures++;
    }
}

static void expect(const char *name, const char *want) {
    char buf[256];
    get(name, buf, sizeof buf);
    if (strcmp(buf, want) != 0) {
        printf("thp-fail: %s reads `%s`, want `%s`\n", name, buf, want);
        failures++;
    }
}

// The active token of a bracketed knob, for restoring it.
static void active(const char *name, char *out, size_t len) {
    char buf[256];
    get(name, buf, sizeof buf);
    char *l = strchr(buf, '['), *r = l ? strchr(l, ']') : NULL;
    if (!l || !r) {
        out[0] = 0;
        return;
    }
    *r = 0;
    snprintf(out, len, "%s", l + 1);
}

int main(void) {
    char old_defrag[64], old_enabled[64], old_ptes[64];
    active("defrag", old_defrag, sizeof old_defrag);
    active("enabled", old_enabled, sizeof old_enabled);
    get("khugepaged/max_ptes_none", old_ptes, sizeof old_ptes);

    // tmpfiles' exact writes.
    check("w! defrag defer+madvise", put("defrag", "defer+madvise\n"), 0);
    expect("defrag", "always defer [defer+madvise] madvise never\n");
    check("w! max_ptes_none 409", put("khugepaged/max_ptes_none", "409\n"), 0);
    expect("khugepaged/max_ptes_none", "409\n");
    check("enabled madvise", put("enabled", "madvise"), 0);
    expect("enabled", "always [madvise] never\n");

    // Linux's EINVAL answers; a refused write changes nothing.
    check("defrag bogus", put("defrag", "bogus\n"), -EINVAL);
    expect("defrag", "always defer [defer+madvise] madvise never\n");
    check("max_ptes_none 512", put("khugepaged/max_ptes_none", "512"), -EINVAL);
    check("max_ptes_none -1", put("khugepaged/max_ptes_none", "-1"), -EINVAL);
    expect("khugepaged/max_ptes_none", "409\n");
    check("enabled sometimes", put("enabled", "sometimes"), -EINVAL);

    if (old_defrag[0]) {
        char v[80];
        snprintf(v, sizeof v, "%s\n", old_defrag);
        put("defrag", v);
    }
    if (old_enabled[0])
        put("enabled", old_enabled);
    if (old_ptes[0])
        put("khugepaged/max_ptes_none", old_ptes);
    if (failures)
        return 1;
    printf("thp-ok\n");
    return 0;
}
