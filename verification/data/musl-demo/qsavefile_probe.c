// Replicate Qt's QSaveFile / KConfig atomic-write sequence and report the
// errno of every step.
//
// On the Fedora KDE image kwin logs, once it gets deep enough into startup:
//
//   Couldn't write "/home/narf/.config/kwinrc" . Disk full?
//   Couldn't write "/home/narf/.config/kglobalshortcutsrc" . Disk full?
//
// "Disk full?" is KConfig GUESSING at the cause; it prints that for any
// failed commit. The image is not full (2.5 GB / 187k inodes free) and the
// directories are uid 1000 owned and writable, so the real failure is one
// of the syscalls below and nothing in the log says which.
//
// KConfig writes through QSaveFile, which is:
//   1. create a temp file in the SAME directory as the target
//   2. write the payload
//   3. fchmod it to the target's mode
//   4. rename() the temp onto the target   <- the atomic swap
//
// Each step prints its own errno, so the failure names a syscall instead of
// a guess. Run as the session user against the real rootfs — earlier ABI
// tests for this ran on memfs, while /home is ext2, and that difference is
// exactly what a memfs-only test cannot see.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int step(const char *what, int rc)
{
    if (rc < 0)
        printf("QSF: %-28s FAILED errno=%d (%s)\n", what, errno, strerror(errno));
    else
        printf("QSF: %-28s ok (%d)\n", what, rc);
    return rc;
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "/home/narf/.config";
    char target[512], tmp[512];
    snprintf(target, sizeof target, "%s/narf-qsf-target", dir);
    snprintf(tmp, sizeof tmp, "%s/narf-qsf-tmp", dir);

    printf("QSF: probing %s as uid=%d gid=%d\n", dir, (int)getuid(), (int)getgid());

    // Is the directory even writable by us? Distinguishes a permission
    // problem from a filesystem-operation problem before we start.
    step("access(dir, W_OK|X_OK)", access(dir, W_OK | X_OK));

    unlink(tmp);
    unlink(target);

    int fd = step("open(tmp, O_CREAT|O_EXCL)",
                  open(tmp, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600));
    if (fd < 0)
        return 1;

    const char *payload = "[General]\nnarf=1\n";
    step("write(tmp)", (int)write(fd, payload, strlen(payload)));
    step("fsync(tmp)", fsync(fd));
    step("fchmod(tmp, 0644)", fchmod(fd, 0644));
    step("close(tmp)", close(fd));

    // THE atomic swap. Same directory, so this is not a cross-device case.
    step("rename(tmp -> target)", rename(tmp, target));

    // Prove the result is actually readable at the target name.
    int rfd = step("open(target, O_RDONLY)", open(target, O_RDONLY | O_CLOEXEC));
    if (rfd >= 0) {
        char buf[64] = {0};
        step("read(target)", (int)read(rfd, buf, sizeof buf - 1));
        close(rfd);
    }

    // Second pass: QSaveFile overwrites an EXISTING file every time after
    // the first, which is the case that actually runs during a session.
    int fd2 = step("open(tmp#2, O_CREAT|O_EXCL)",
                   open(tmp, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600));
    if (fd2 >= 0) {
        step("write(tmp#2)", (int)write(fd2, payload, strlen(payload)));
        step("close(tmp#2)", close(fd2));
        step("rename over EXISTING", rename(tmp, target));
    }

    unlink(tmp);
    unlink(target);
    printf("QSF: done\n");
    return 0;
}
