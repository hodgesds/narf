// execve of a set-user-ID / set-group-ID binary changes credentials exactly
// the way Linux does (fs/exec.c::bprm_fill_uid + security/commoncap.c::
// cap_bprm_creds_from_file + begin_new_exec/commit_creds), and every guard
// on that transition holds.
//
// On a CachyOS guest `sudo` failed with "effective uid is not 0": the
// distro runs chrooted, and the set-user-ID decision re-resolved the exec
// path WITHOUT the chroot, so it never found /usr/bin/sudo and conferred
// nothing. The "chroot" case below is that exact shape.
//
// Runs as root. Copies itself onto two private tmpfs mounts (one plain, one
// MS_NOSUID), stages helpers with various modes, and for each case forks a
// child that drops to an unprivileged uid/gid and execs a helper. The helper
// (this same binary, argv "--report <fd>") writes back what the new image
// sees: getresuid/getresgid, fsuid, getauxval(AT_SECURE/AT_UID/AT_EUID/
// AT_GID/AT_EGID) and prctl(PR_GET_DUMPABLE).
//
// Linux expectations (fs.suid_dumpable = 0, the default):
//   setuid-root exec as U        -> r=U e=0 s=0 fs=0, AT_SECURE=1, dumpable=0
//   same, from inside a chroot   -> identical
//   plain 0755 exec as U         -> r=e=s=fs=U, AT_SECURE=0, dumpable=1
//   plain exec as root           -> all 0, AT_SECURE=0, dumpable=1
//   setuid on a nosuid mount     -> r=e=s=U, AT_SECURE=0, dumpable=1
//   setuid with no_new_privs     -> r=e=s=U, AT_SECURE=0, dumpable=1
//   02745 (setgid, no g+x)       -> egid unchanged, AT_SECURE=0
//   02755 (setgid, g+x)          -> egid=0, sgid=0, AT_SECURE=1, dumpable=0
//   setuid SCRIPT, plain interp  -> nothing (the script's bits are ignored)
//   plain script, setuid interp  -> euid=0 (the INTERPRETER's bits apply)
//   setuid non-ELF (ENOEXEC)     -> execve fails, caller's euid unchanged
//
// Success token "setuid-exec-ok"; each failure prints "setuid-exec-fail: ...".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/fsuid.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define U 4711
#define G 4712

static char self_path[512];
static char base[64];
static int failures;

// ── helper side ─────────────────────────────────────────────────────────

static int report(int fd, const char *tag) {
    uid_t r, e, s;
    gid_t rg, eg, sg;
    getresuid(&r, &e, &s);
    getresgid(&rg, &eg, &sg);
    int fsuid = setfsuid(-1);
    int dump = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    char buf[256];
    int n = snprintf(buf, sizeof buf, "%s %u %u %u %u %u %u %d %lu %d %lu %lu %lu %lu\n", tag,
                     (unsigned)r, (unsigned)e, (unsigned)s, (unsigned)rg, (unsigned)eg,
                     (unsigned)sg, fsuid, getauxval(AT_SECURE), dump, getauxval(AT_UID),
                     getauxval(AT_EUID), getauxval(AT_GID), getauxval(AT_EGID));
    return write(fd, buf, n) == n ? 0 : 1;
}

// ── parent side ─────────────────────────────────────────────────────────

struct want {
    long ruid, euid, suid, rgid, egid, sgid, fsuid, secure, dumpable;
};
#define ANY (-1L)

static int copy_file(const char *from, const char *to, mode_t mode) {
    int in = open(from, O_RDONLY | O_CLOEXEC);
    if (in < 0)
        return -1;
    int out = open(to, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
    if (out < 0) {
        close(in);
        return -1;
    }
    char buf[65536];
    ssize_t n;
    int rc = 0;
    while ((n = read(in, buf, sizeof buf)) > 0)
        if (write(out, buf, n) != n) {
            rc = -1;
            break;
        }
    if (n < 0)
        rc = -1;
    close(in);
    close(out);
    // chown first: a later chown would clear the set-id bits.
    if (rc == 0 && (chown(to, 0, 0) != 0 || chmod(to, mode) != 0))
        rc = -1;
    return rc;
}

static int write_file(const char *path, const char *data, size_t len, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
    if (fd < 0)
        return -1;
    int ok = write(fd, data, len) == (ssize_t)len;
    close(fd);
    if (!ok || chown(path, 0, 0) != 0 || chmod(path, mode) != 0)
        return -1;
    return 0;
}

enum { F_DROP = 1, F_NNP = 2, F_CHROOT = 4, F_EXPECT_FAIL = 8 };

// Fork, optionally chroot/drop/NNP, exec `path`, and compare the report.
static void run_case(const char *name, int flags, const char *chroot_dir, const char *path,
                     struct want w) {
    int p[2];
    if (pipe(p) != 0) {
        printf("setuid-exec-fail: case=%s pipe errno=%d\n", name, errno);
        failures++;
        return;
    }
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        if (flags & F_CHROOT) {
            if (chroot(chroot_dir) != 0 || chdir("/") != 0) {
                dprintf(p[1], "SETUPFAIL chroot %d\n", errno);
                _exit(1);
            }
        }
        if (flags & F_DROP) {
            if (setgroups(0, NULL) != 0 || setresgid(G, G, G) != 0 ||
                setresuid(U, U, U) != 0) {
                dprintf(p[1], "SETUPFAIL drop %d\n", errno);
                _exit(1);
            }
        }
        if ((flags & F_NNP) && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            dprintf(p[1], "SETUPFAIL nnp %d\n", errno);
            _exit(1);
        }
        char fdstr[16];
        snprintf(fdstr, sizeof fdstr, "%d", p[1]);
        char *argv[] = {(char *)path, "--report", fdstr, NULL};
        char *envp[] = {"PATH=/bin", NULL};
        execve(path, argv, envp);
        int err = errno;
        // The exec failed: report what THIS image is left holding.
        char tag[32];
        snprintf(tag, sizeof tag, "EXECFAIL=%d", err);
        report(p[1], tag);
        _exit(0);
    }
    close(p[1]);
    char buf[512] = {0};
    size_t got = 0;
    ssize_t n;
    while (got < sizeof buf - 1 && (n = read(p[0], buf + got, sizeof buf - 1 - got)) > 0)
        got += n;
    close(p[0]);
    int status = 0;
    waitpid(pid, &status, 0);

    char tag[32];
    unsigned r, e, s, rg, eg, sg;
    int fsuid, dump;
    unsigned long secure, at_uid, at_euid, at_gid, at_egid;
    if (sscanf(buf, "%31s %u %u %u %u %u %u %d %lu %d %lu %lu %lu %lu", tag, &r, &e, &s, &rg,
               &eg, &sg, &fsuid, &secure, &dump, &at_uid, &at_euid, &at_gid,
               &at_egid) != 14) {
        printf("setuid-exec-fail: case=%s no report (status=%#x) got=\"%s\"\n", name, status,
               buf);
        failures++;
        return;
    }
    int bad = 0;
    if (flags & F_EXPECT_FAIL) {
        if (strcmp(tag, "EXECFAIL=8") != 0) { // ENOEXEC
            printf("setuid-exec-fail: case=%s expected ENOEXEC, tag=%s\n", name, tag);
            bad = 1;
        }
    } else if (strcmp(tag, "OK") != 0) {
        printf("setuid-exec-fail: case=%s exec did not run the helper, tag=%s\n", name, tag);
        bad = 1;
    }
#define CHECK(field, val)                                                                   \
    if (w.field != ANY && (long)(val) != w.field) {                                          \
        printf("setuid-exec-fail: case=%s %s=%ld want %ld\n", name, #field, (long)(val),    \
               w.field);                                                                     \
        bad = 1;                                                                             \
    }
    CHECK(ruid, r);
    CHECK(euid, e);
    CHECK(suid, s);
    CHECK(rgid, rg);
    CHECK(egid, eg);
    CHECK(sgid, sg);
    CHECK(fsuid, fsuid);
    if (!(flags & F_EXPECT_FAIL)) {
        CHECK(secure, secure);
        CHECK(dumpable, dump);
        // AT_UID/AT_EUID/AT_GID/AT_EGID are the NEW credentials.
        if (at_uid != r || at_euid != e || at_gid != rg || at_egid != eg) {
            printf("setuid-exec-fail: case=%s auxv ids %lu/%lu/%lu/%lu != creds %u/%u/%u/%u\n",
                   name, at_uid, at_euid, at_gid, at_egid, r, e, rg, eg);
            bad = 1;
        }
    }
    if (bad)
        failures++;
    else
        printf("setuid-exec: case=%s ok\n", name);
}

static int do_mount(const char *dir, unsigned long flags) {
    if (mkdir(dir, 0755) != 0 && errno != EEXIST)
        return -1;
    return mount("tmpfs", dir, "tmpfs", flags, "mode=0755");
}

int main(int argc, char **argv) {
    for (int i = 1; i + 1 < argc; i++)
        if (strcmp(argv[i], "--report") == 0)
            return report(atoi(argv[i + 1]), "OK");

    if (getuid() != 0 || geteuid() != 0) {
        printf("setuid-exec-fail: must start as root (uid=%u euid=%u)\n", getuid(), geteuid());
        return 1;
    }
    ssize_t n = readlink("/proc/self/exe", self_path, sizeof self_path - 1);
    if (n <= 0) {
        printf("setuid-exec-fail: readlink /proc/self/exe errno=%d\n", errno);
        return 1;
    }
    self_path[n] = 0;

    snprintf(base, sizeof base, "/tmp/setuid-exec.XXXXXX");
    if (!mkdtemp(base)) {
        printf("setuid-exec-fail: mkdtemp errno=%d\n", errno);
        return 1;
    }
    char plain[96], nosuid[96];
    snprintf(plain, sizeof plain, "%s/plain", base);
    snprintf(nosuid, sizeof nosuid, "%s/nosuid", base);
    if (do_mount(plain, 0) != 0 || do_mount(nosuid, MS_NOSUID) != 0) {
        printf("setuid-exec-fail: mount tmpfs errno=%d\n", errno);
        return 1;
    }

    char p_suid[128], p_plain[128], p_sgid_nox[128], p_sgid[128], p_nosuid[128];
    char p_suid_script[128], p_script_suid_interp[128], p_bad_elf[128], lib[128], ldso[160];
    snprintf(p_suid, sizeof p_suid, "%s/suid", plain);
    snprintf(p_plain, sizeof p_plain, "%s/plain", plain);
    snprintf(p_sgid_nox, sizeof p_sgid_nox, "%s/sgid-nox", plain);
    snprintf(p_sgid, sizeof p_sgid, "%s/sgid", plain);
    snprintf(p_nosuid, sizeof p_nosuid, "%s/suid", nosuid);
    snprintf(p_suid_script, sizeof p_suid_script, "%s/suid-script", plain);
    snprintf(p_script_suid_interp, sizeof p_script_suid_interp, "%s/script-suid-interp", plain);
    snprintf(p_bad_elf, sizeof p_bad_elf, "%s/bad-elf", plain);
    if (copy_file(self_path, p_suid, 04755) || copy_file(self_path, p_plain, 0755) ||
        copy_file(self_path, p_sgid_nox, 02745) || copy_file(self_path, p_sgid, 02755) ||
        copy_file(self_path, p_nosuid, 04755)) {
        printf("setuid-exec-fail: staging helpers errno=%d\n", errno);
        return 1;
    }
    char script[192];
    int len = snprintf(script, sizeof script, "#!%s\n", p_plain);
    if (write_file(p_suid_script, script, len, 04755) != 0) {
        printf("setuid-exec-fail: staging setuid script errno=%d\n", errno);
        return 1;
    }
    len = snprintf(script, sizeof script, "#!%s\n", p_suid);
    if (write_file(p_script_suid_interp, script, len, 0755) != 0) {
        printf("setuid-exec-fail: staging script errno=%d\n", errno);
        return 1;
    }
    // Not ELF, not "#!", and past the 64-byte "too small" gate: the binfmt
    // search fails with ENOEXEC after the set-user-ID decision was made.
    char junk[256];
    memset(junk, 'Z', sizeof junk);
    if (write_file(p_bad_elf, junk, sizeof junk, 04755) != 0) {
        printf("setuid-exec-fail: staging non-ELF errno=%d\n", errno);
        return 1;
    }
    // A dynamically linked helper needs its interpreter inside the chroot.
    snprintf(lib, sizeof lib, "%s/lib", plain);
    snprintf(ldso, sizeof ldso, "%s/ld-musl-x86_64.so.1", lib);
    if (access("/lib/ld-musl-x86_64.so.1", R_OK) == 0) {
        mkdir(lib, 0755);
        if (copy_file("/lib/ld-musl-x86_64.so.1", ldso, 0755) != 0) {
            printf("setuid-exec-fail: staging ld-musl in the chroot errno=%d\n", errno);
            return 1;
        }
    }

    struct want suid_root = {U, 0, 0, G, G, G, 0, 1, 0};
    struct want unchanged = {U, U, U, G, G, G, U, 0, 1};

    run_case("setuid-root", F_DROP, NULL, p_suid, suid_root);
    run_case("chroot-setuid-root", F_DROP | F_CHROOT, plain, "/suid", suid_root);
    run_case("plain", F_DROP, NULL, p_plain, unchanged);
    run_case("plain-as-root", 0, NULL, p_plain, (struct want){0, 0, 0, 0, 0, 0, 0, 0, 1});
    run_case("nosuid-mount", F_DROP, NULL, p_nosuid, unchanged);
    run_case("no-new-privs", F_DROP | F_NNP, NULL, p_suid, unchanged);
    run_case("setgid-no-group-exec", F_DROP, NULL, p_sgid_nox, unchanged);
    run_case("setgid", F_DROP, NULL, p_sgid, (struct want){U, U, U, G, 0, 0, U, 1, 0});
    run_case("setuid-script", F_DROP, NULL, p_suid_script, unchanged);
    run_case("script-setuid-interp", F_DROP, NULL, p_script_suid_interp, suid_root);
    run_case("setuid-enoexec", F_DROP | F_EXPECT_FAIL, NULL, p_bad_elf,
             (struct want){U, U, U, G, G, G, U, ANY, ANY});

    umount2(plain, MNT_DETACH);
    umount2(nosuid, MNT_DETACH);
    rmdir(plain);
    rmdir(nosuid);
    rmdir(base);
    if (failures) {
        printf("setuid-exec-fail: %d case(s) failed\n", failures);
        return 1;
    }
    printf("setuid-exec-ok\n");
    return 0;
}
