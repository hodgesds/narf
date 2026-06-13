// Landlock smoke: real path-based access enforcement. Build a ruleset that
// handles READ_FILE|WRITE_FILE, allow those rights beneath one file, then
// restrict_self and prove enforcement: the allowed file still opens, but a
// sibling outside any rule is denied with EACCES. Issued raw (no musl
// wrappers). Success token "landlock-ok".
//
// Build: see REGEN_landlock_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif
#ifndef SYS_landlock_add_rule
#define SYS_landlock_add_rule 445
#endif
#ifndef SYS_landlock_restrict_self
#define SYS_landlock_restrict_self 446
#endif

#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#define LANDLOCK_RULE_PATH_BENEATH 1
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)

struct ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
};
struct path_beneath_attr {
    uint64_t allowed_access;
    int32_t parent_fd;
} __attribute__((packed));

static void w(const char *m) { write(1, m, strlen(m)); }

#define ALLOW "/dev/shm/ll_allow"
#define DENY "/dev/shm/ll_deny"

int main(void) {
    // ABI version query must report a positive version.
    long ver = syscall(SYS_landlock_create_ruleset, (void *)0, (size_t)0,
                       (long)LANDLOCK_CREATE_RULESET_VERSION);
    if (ver < 1) { w("landlock-fail: version\n"); return 1; }

    // Two target files, created (and the denied one written) up front.
    int a = open(ALLOW, O_CREAT | O_RDWR, 0600);
    int d = open(DENY, O_CREAT | O_RDWR, 0600);
    if (a < 0 || d < 0) { w("landlock-fail: setup\n"); return 1; }
    write(a, "x", 1);
    write(d, "x", 1);
    close(a);
    close(d);

    // Ruleset handling file read+write.
    struct ruleset_attr ra = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
        .handled_access_net = 0,
    };
    long rs = syscall(SYS_landlock_create_ruleset, &ra, sizeof ra, 0L);
    if (rs < 0) { w("landlock-fail: create\n"); return 1; }

    // Allow read+write beneath ALLOW (parent_fd identifies the path).
    int pf = open(ALLOW, O_RDONLY);
    if (pf < 0) { w("landlock-fail: parent-open\n"); return 1; }
    struct path_beneath_attr pba = {
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
        .parent_fd = pf,
    };
    if (syscall(SYS_landlock_add_rule, rs, (long)LANDLOCK_RULE_PATH_BENEATH, &pba, 0L) != 0) {
        w("landlock-fail: add_rule\n"); return 1;
    }
    close(pf);

    // Apply the restriction (irreversible) to this task.
    if (syscall(SYS_landlock_restrict_self, rs, 0L) != 0) {
        w("landlock-fail: restrict\n"); return 1;
    }

    // The allowed file still opens for read+write.
    int fa = open(ALLOW, O_RDWR);
    if (fa < 0) { w("landlock-fail: allow-denied\n"); return 1; }
    close(fa);

    // The sibling outside any rule is denied with EACCES — for write...
    if (open(DENY, O_RDWR) != -1 || errno != EACCES) {
        w("landlock-fail: deny-write\n"); return 1;
    }
    // ...and for read.
    if (open(DENY, O_RDONLY) != -1 || errno != EACCES) {
        w("landlock-fail: deny-read\n"); return 1;
    }

    w("landlock-ok\n");
    return 0;
}
