// systemd-update-utmp's boot record: pututxline(/run/utmp) + updwtmpx
// (/var/log/wtmp). systemd's write_entry_wtmp() does
//
//     errno = 0; updwtmpx(WTMPX_FILE, &store); return -errno;
//
// so ANY syscall inside glibc's updwtmpx that leaves errno set — even one
// glibc tolerates — becomes "Failed to write utmp record: <errno>". The glibc
// sequence (strace, glibc 2.42, login/utmp_file.c):
//
//   openat(path, O_RDONLY|O_CLOEXEC)  lseek(fd, 0, SEEK_SET)
//   openat(path, O_RDWR|O_CLOEXEC)    dup2(rw, fd)  close(rw)
//   alarm(0)  rt_sigaction(SIGALRM)  alarm(10)
//   fcntl(fd, F_SETLKW, {F_WRLCK, SEEK_SET, 0, 0})
//   alarm(0)  rt_sigaction(SIGALRM, old)
//   pread64(fd, buf, 384, 0)  lseek(fd, 0, SEEK_END)  lseek(fd, 0, SEEK_SET)
//   write(fd, rec, 384)  fcntl(fd, F_SETLKW, {F_UNLCK, ...})  close(fd)
//   openat(wtmp, O_WRONLY|O_CLOEXEC)  ...lock...  lseek(fd, 0, SEEK_END)
//   write(fd, rec, 384)  ...unlock...  close(fd)
//
// This replays that sequence with raw syscalls (musl's utmpx is a stub) and,
// on glibc, through pututxline/updwtmpx with systemd's errno check.
// Success token "utmp-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __GLIBC__
#include <utmpx.h>
#endif

#define REC 384

static int failures;

static void bad(const char *what, int err) {
    printf("utmp-fail: %s (errno %d %s)\n", what, err, strerror(err));
    failures++;
}

static void on_alarm(int sig) { (void)sig; }

// glibc try_file_lock(): SIGALRM-bounded F_SETLKW.
static int locked(int fd, short type) {
    struct sigaction action = {0}, old;
    unsigned prev = alarm(0);
    action.sa_handler = on_alarm;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, &old) != 0)
        bad("rt_sigaction(SIGALRM)", errno);
    alarm(10);
    struct flock fl = {.l_type = type, .l_whence = SEEK_SET};
    errno = 0;
    int r = fcntl(fd, F_SETLKW, &fl);
    int saved = errno;
    alarm(0);
    sigaction(SIGALRM, &old, NULL);
    if (prev)
        alarm(prev);
    errno = saved;
    return r;
}

static void raw_utmp(const char *path) {
    char rec[REC], buf[REC];
    memset(rec, 0, sizeof rec);
    rec[0] = 2; // BOOT_TIME
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        bad("open utmp O_RDONLY", errno);
        return;
    }
    if (lseek(fd, 0, SEEK_SET) != 0)
        bad("lseek(0, SEEK_SET)", errno);
    int rw = open(path, O_RDWR | O_CLOEXEC);
    if (rw < 0)
        bad("open utmp O_RDWR", errno);
    else if (dup2(rw, fd) != fd)
        bad("dup2(rw, fd)", errno);
    close(rw);
    if (locked(fd, F_WRLCK) != 0)
        bad("fcntl(F_SETLKW, F_WRLCK) on the dup2'd O_RDWR fd", errno);
    ssize_t n = pread(fd, buf, REC, 0);
    if (n < 0)
        bad("pread64(384, 0)", errno);
    off_t end = lseek(fd, 0, SEEK_END);
    if (end < 0)
        bad("lseek(0, SEEK_END)", errno);
    if (lseek(fd, 0, SEEK_SET) != 0)
        bad("lseek back to 0", errno);
    if (write(fd, rec, REC) != REC)
        bad("write(utmp record)", errno);
    if (locked(fd, F_UNLCK) != 0)
        bad("fcntl(F_SETLKW, F_UNLCK)", errno);
    close(fd);
}

static void raw_wtmp(const char *path) {
    char rec[REC];
    memset(rec, 0, sizeof rec);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        bad("open wtmp O_WRONLY", errno);
        return;
    }
    if (locked(fd, F_WRLCK) != 0)
        bad("wtmp fcntl(F_SETLKW, F_WRLCK)", errno);
    off_t before = lseek(fd, 0, SEEK_END);
    if (before < 0)
        bad("wtmp lseek(0, SEEK_END)", errno);
    if (write(fd, rec, REC) != REC)
        bad("wtmp write", errno);
    if (lseek(fd, 0, SEEK_END) != before + REC)
        bad("wtmp did not grow by one record", errno);
    if (locked(fd, F_UNLCK) != 0)
        bad("wtmp fcntl(F_SETLKW, F_UNLCK)", errno);
    close(fd);
}

int main(void) {
    const char *utmp = "/tmp/utmp-smoke.utmp";
    const char *wtmp = "/tmp/utmp-smoke.wtmp";
    unlink(utmp);
    unlink(wtmp);
    close(open(utmp, O_CREAT | O_RDWR, 0664));
    close(open(wtmp, O_CREAT | O_RDWR, 0664));

    raw_utmp(utmp);
    raw_utmp(utmp); // second pass reads the first record back
    raw_wtmp(wtmp);

    // Negative: a write lock needs a writable description (EBADF), and an
    // unknown l_type is EINVAL (`flock_to_posix_lock` / `assign_type`).
    int ro = open(utmp, O_RDONLY);
    struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
    if (fcntl(ro, F_SETLKW, &fl) == 0 || errno != EBADF)
        bad("F_WRLCK on an O_RDONLY fd must be EBADF", errno);
    fl.l_type = 7;
    if (fcntl(ro, F_SETLK, &fl) == 0 || errno != EINVAL)
        bad("an unknown l_type must be EINVAL", errno);
    close(ro);

#ifdef __GLIBC__
    struct utmpx u;
    memset(&u, 0, sizeof u);
    u.ut_type = BOOT_TIME;
    strcpy(u.ut_user, "reboot");
    strcpy(u.ut_line, "~");
    strcpy(u.ut_id, "~~");
    if (utmpxname(utmp) != 0)
        bad("utmpxname", errno);
    setutxent();
    errno = 0;
    if (!pututxline(&u))
        bad("pututxline", errno);
    endutxent();
    // systemd's check: errno must stay 0 across a successful updwtmpx.
    errno = 0;
    updwtmpx(wtmp, &u);
    if (errno != 0)
        bad("updwtmpx left errno set (systemd reports it)", errno);
#endif

    unlink(utmp);
    unlink(wtmp);
    if (failures)
        return 1;
    printf("utmp-ok\n");
    return 0;
}
