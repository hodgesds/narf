// POSIX ACLs the way systemd-tmpfiles applies them (tmpfiles.d/systemd.conf:
// `a+ /var/log/journal - - - - d:group:adm:r-x,...,group:wheel:r-x`).
//
// tmpfiles opens the path O_PATH and calls libacl's acl_get_file /
// acl_set_file on "/proc/self/fd/N" — i.e. getxattr/setxattr of
// system.posix_acl_{access,default} THROUGH the procfs magic link. On NARF
// that failed ("ACL operation on /var/log/journal failed: No such file or
// directory") and the journal directory never got its group ACLs. Then a
// file created in a directory with a default ACL must inherit it
// (posix_acl_create) with the mode narrowed through it instead of the
// umask, and chmod must keep the ACL mask in step (posix_acl_chmod).
//
// Uses raw xattr blobs (no libacl). Runs unprivileged on a file it owns.
// Success token "acl-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#define ACL_USER_OBJ 0x01
#define ACL_USER 0x02
#define ACL_GROUP_OBJ 0x04
#define ACL_GROUP 0x08
#define ACL_MASK 0x10
#define ACL_OTHER 0x20

struct ent {
    uint16_t tag, perm;
    uint32_t id;
};

static int failures;

static void bad(const char *what, int err) {
    printf("acl-fail: %s (errno %d %s)\n", what, err, strerror(err));
    failures++;
}

static size_t blob(unsigned char *out, const struct ent *e, int n) {
    uint32_t v = 2; // POSIX_ACL_XATTR_VERSION
    memcpy(out, &v, 4);
    for (int i = 0; i < n; i++)
        memcpy(out + 4 + 8 * i, &e[i], 8);
    return 4 + 8 * (size_t)n;
}

// group:<gid>:r-x with user::rwx group::r-x mask::r-x other::---
static size_t group_acl(unsigned char *out, uint32_t gid) {
    struct ent e[] = {
        {ACL_USER_OBJ, 7, 0xFFFFFFFF}, {ACL_GROUP_OBJ, 5, 0xFFFFFFFF},
        {ACL_GROUP, 5, gid},           {ACL_MASK, 5, 0xFFFFFFFF},
        {ACL_OTHER, 0, 0xFFFFFFFF},
    };
    return blob(out, e, 5);
}

static int has_group_entry(const unsigned char *b, ssize_t n, uint32_t gid, uint16_t *perm) {
    for (ssize_t off = 4; off + 8 <= n; off += 8) {
        struct ent e;
        memcpy(&e, b + off, 8);
        if (e.tag == ACL_GROUP && e.id == gid) {
            if (perm)
                *perm = e.perm;
            return 1;
        }
    }
    return 0;
}

int main(void) {
    char dir[] = "/tmp/acl-smoke-XXXXXX";
    if (!mkdtemp(dir)) {
        bad("mkdtemp", errno);
        return 1;
    }
    const uint32_t gid = 4242;
    unsigned char acl[64], got[256];
    size_t len = group_acl(acl, gid);

    // ── tmpfiles' path: O_PATH fd + /proc/self/fd/N ─────────────────
    int pfd = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (pfd < 0) {
        bad("open O_PATH", errno);
        return 1;
    }
    char proc[64];
    snprintf(proc, sizeof proc, "/proc/self/fd/%d", pfd);
    // libacl's acl_get_file first: no ACL yet is ENODATA, not ENOENT.
    if (getxattr(proc, "system.posix_acl_access", got, sizeof got) >= 0 || errno != ENODATA)
        bad("getxattr(/proc/self/fd/N) before set must be ENODATA", errno);
    if (setxattr(proc, "system.posix_acl_access", acl, len, 0) != 0)
        bad("setxattr access ACL via /proc/self/fd/N", errno);
    if (setxattr(proc, "system.posix_acl_default", acl, len, 0) != 0)
        bad("setxattr default ACL via /proc/self/fd/N", errno);
    ssize_t n = getxattr(dir, "system.posix_acl_access", got, sizeof got);
    if (n < 0 || !has_group_entry(got, n, gid, NULL))
        bad("the access ACL set through /proc/self/fd/N is not on the directory", errno);
    // posix_acl_update_mode: group bits of the mode are the mask (r-x).
    struct stat st;
    if (stat(dir, &st) != 0 || (st.st_mode & 0777) != 0750)
        printf("acl-fail: dir mode %o after access ACL, want 750\n", st.st_mode & 0777),
            failures++;
    close(pfd);

    // ── inheritance: posix_acl_create ───────────────────────────────
    umask(077); // must NOT apply: the default ACL replaces the umask
    char file[128];
    snprintf(file, sizeof file, "%s/f", dir);
    int fd = open(file, O_CREAT | O_WRONLY | O_CLOEXEC, 0666);
    if (fd < 0)
        bad("create in a default-ACL directory", errno);
    else
        close(fd);
    n = getxattr(file, "system.posix_acl_access", got, sizeof got);
    if (n < 0 || !has_group_entry(got, n, gid, NULL))
        bad("a new file did not inherit the parent's default ACL", errno);
    if (stat(file, &st) != 0 || (st.st_mode & 0777) != 0640)
        printf("acl-fail: inherited file mode %o, want 640 (0666 masked by the ACL)\n",
               st.st_mode & 0777),
            failures++;
    if (getxattr(file, "system.posix_acl_default", got, sizeof got) >= 0 || errno != ENODATA)
        bad("a regular file must not carry a default ACL", errno);
    char sub[128];
    snprintf(sub, sizeof sub, "%s/d", dir);
    if (mkdir(sub, 0777) != 0)
        bad("mkdir in a default-ACL directory", errno);
    n = getxattr(sub, "system.posix_acl_default", got, sizeof got);
    if (n < 0 || !has_group_entry(got, n, gid, NULL))
        bad("a new subdirectory did not inherit the default ACL as its default", errno);

    // ── chmod keeps the mask in step: posix_acl_chmod ───────────────
    if (chmod(file, 0600) != 0)
        bad("chmod", errno);
    uint16_t perm = 99;
    n = getxattr(file, "system.posix_acl_access", got, sizeof got);
    for (ssize_t off = 4; n > 0 && off + 8 <= n; off += 8) {
        struct ent e;
        memcpy(&e, got + off, 8);
        if (e.tag == ACL_MASK)
            perm = e.perm;
    }
    if (perm != 0)
        printf("acl-fail: chmod 0600 left mask perm %u, want 0\n", perm), failures++;

    // ── negatives ───────────────────────────────────────────────────
    if (setxattr(file, "system.posix_acl_default", acl, len, 0) == 0 || errno != EACCES)
        bad("a default ACL on a regular file must be EACCES", errno);
    unsigned char junk[8] = {2, 0, 0, 0, 0x40, 0, 7, 0}; // unknown tag
    if (setxattr(file, "system.posix_acl_access", junk, sizeof junk, 0) == 0 || errno != EINVAL)
        bad("a malformed ACL must be EINVAL", errno);
    unsigned char v1[4] = {1, 0, 0, 0}; // wrong a_version
    if (setxattr(file, "system.posix_acl_access", v1, sizeof v1, 0) == 0 || errno != EOPNOTSUPP)
        bad("an unknown ACL version must be EOPNOTSUPP", errno);

    unlink(file);
    rmdir(sub);
    rmdir(dir);
    if (failures)
        return 1;
    printf("acl-ok\n");
    return 0;
}
