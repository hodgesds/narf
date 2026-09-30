// A pty slave's owner and mode can be changed, as sudo's use_pty needs.
//
// sudo's get_pty() (src/get_pty.c) succeeds only
// `if (openpty(...) == 0) { if (chown(name, ttyuid, ttygid) == 0) ... }`,
// and its other paths chown/chmod the slave too. Linux devpts inodes take the
// default simple_setattr, with setattr_prepare's permission rules. On NARF
// /dev/pts/N had no set_owners/set_perms, so chown failed EOPNOTSUPP and sudo
// printed "unable to allocate pty: Operation not supported" after a correct
// password.
//
// As root (the NARF harness):
//   - chown(ptsname, 1234, 5) and fchown(slave, ...) succeed and stat shows it;
//   - chmod(ptsname, 0600) and fchmod(slave, 0620) succeed and stat shows it;
//   - in a child running as uid 1234 (the new owner): chmod of its own pts
//     succeeds; chown(pts, 0, -1) is EPERM (chown_ok needs CAP_CHOWN).
// As an ordinary user (a Linux host run): chown to your own uid/gid and chmod
// of your own pts succeed; chown to uid 0 is EPERM.
//
// In both modes a master fd reports the ptmx node it was opened through:
// fstat(master) equals stat("/dev/ptmx") in inode, mode, owner and rdev (the
// master's struct file stays on that inode — a real devtmpfs node on most
// systems, devpts's own ptmx behind a /dev/ptmx symlink on others).
//
// Success token "pts-chown-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int failed;

static void fail(const char *what, long v) {
    printf("pts-chown-fail: %s (%ld)\n", what, v);
    failed = 1;
}

static void expect_owner(const char *name, uid_t uid, gid_t gid, const char *what) {
    struct stat st;
    if (stat(name, &st) != 0)
        fail("stat errno", errno);
    else if (st.st_uid != uid || st.st_gid != gid)
        fail(what, (long)st.st_uid * 100000 + st.st_gid);
}

static void expect_mode(const char *name, mode_t perms, const char *what) {
    struct stat st;
    if (stat(name, &st) != 0)
        fail("stat errno", errno);
    else if ((st.st_mode & 07777) != perms)
        fail(what, (long)(st.st_mode & 07777));
}

int main(void) {
    int m, s;
    char name[64];
    if (openpty(&m, &s, name, NULL, NULL) != 0) {
        printf("pts-chown-fail: openpty errno=%d\n", errno);
        return 1;
    }

    {
        struct stat ms, ps;
        if (fstat(m, &ms) != 0 || stat("/dev/ptmx", &ps) != 0)
            fail("fstat(master)/stat(/dev/ptmx) errno", errno);
        else if (ms.st_ino != ps.st_ino || ms.st_mode != ps.st_mode || ms.st_uid != ps.st_uid ||
                 ms.st_gid != ps.st_gid || ms.st_rdev != ps.st_rdev)
            fail("fstat(master) is not /dev/ptmx's identity (master mode)", (long)ms.st_mode);
    }

    if (geteuid() == 0) {
        // sudo's call: chown(name, ttyuid, ttygid).
        if (chown(name, 1234, 5) != 0)
            fail("chown(pts, 1234, 5) errno", errno);
        expect_owner(name, 1234, 5, "chown did not change the owner (uid*100000+gid)");
        if (fchown(s, 1234, 7) != 0)
            fail("fchown(slave, 1234, 7) errno", errno);
        expect_owner(name, 1234, 7, "fchown did not change the group (uid*100000+gid)");
        if (chown(name, (uid_t)-1, 5) != 0)
            fail("chown(pts, -1, 5) errno", errno);
        expect_owner(name, 1234, 5, "chown -1 did not keep the owner (uid*100000+gid)");
        if (chmod(name, 0600) != 0)
            fail("chmod(pts, 0600) errno", errno);
        expect_mode(name, 0600, "chmod did not change the mode");
        if (fchmod(s, 0620) != 0)
            fail("fchmod(slave, 0620) errno", errno);
        expect_mode(name, 0620, "fchmod did not change the mode");

        pid_t c = fork();
        if (c == 0) {
            if (setgid(5) != 0 || setuid(1234) != 0)
                _exit(10);
            if (chmod(name, 0600) != 0)
                _exit(11);
            if (chown(name, 0, (gid_t)-1) != -1 || errno != EPERM)
                _exit(12);
            _exit(0);
        }
        int st = 0;
        waitpid(c, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
            fail("owner (uid 1234) checks failed, child status", st);
        expect_mode(name, 0600, "the owner's chmod did not stick");
    } else {
        if (chown(name, getuid(), getgid()) != 0)
            fail("chown of own pts to own uid/gid errno", errno);
        expect_owner(name, getuid(), getgid(), "chown did not stick (uid*100000+gid)");
        if (chmod(name, 0600) != 0)
            fail("chmod of own pts errno", errno);
        expect_mode(name, 0600, "chmod did not change the mode");
        if (chown(name, 0, (gid_t)-1) != -1 || errno != EPERM)
            fail("chown of own pts to uid 0 was not EPERM, errno", errno);
    }

    if (failed)
        return 1;
    printf("pts-chown-ok\n");
    return 0;
}
