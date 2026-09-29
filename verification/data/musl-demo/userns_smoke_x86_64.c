// Real userspace coverage of kernel-global credentials and procfs user maps.
// Reference: /usr/src/linux/{kernel/user_namespace.c,kernel/sys.c,fs/proc/base.c}.
// Run with: cargo xtask musl-demo --features=container --group=userns
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "userns-fail: line %d errno=%d\n", __LINE__, errno); exit(1); } } while (0)

static int mapfd(const char *name, int flags) {
    char path[80];
    snprintf(path, sizeof(path), "/proc/%ld/%s", (long)getpid(), name);
    int fd = open(path, flags);
    CHECK(fd >= 0);
    return fd;
}

static void mapwrite(const char *name, const char *map) {
    int fd = mapfd(name, O_WRONLY);
    CHECK(write(fd, map, strlen(map)) == (ssize_t)strlen(map));
    CHECK(close(fd) == 0);
}

static int child_userns(void *arg) {
    (void)arg;
    CHECK(getuid() == 65534 && getgid() == 65534);
    mapwrite("uid_map", "9 42 1\n");
    mapwrite("gid_map", "10 43 1\n");
    CHECK(getuid() == 9 && getgid() == 10);
    uid_t r, e, saved;
    CHECK(getresuid(&r, &e, &saved) == 0 && r == 9 && e == 9 && saved == 9);
    return 0;
}

int main(void) {
    // NARF's boot /tmp need not be world-writable. Give the test a private
    // directory before dropping host privilege.
    char directory[80], path[96];
    snprintf(directory, sizeof(directory), "/tmp/userns_%ld", (long)getpid());
    CHECK(mkdir(directory, 0700) == 0);
    CHECK(chown(directory, 1000, 1000) == 0);
    snprintf(path, sizeof(path), "%s/identity", directory);
    gid_t groups[] = {1000, 2000};
    CHECK(setgroups(2, groups) == 0);
    CHECK(setresgid(1000, 1000, 1000) == 0);
    CHECK(setresuid(1000, 1000, 1000) == 0);
    CHECK(prctl(PR_SET_DUMPABLE, 1) == 0);
    int owned = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(owned >= 0);
    CHECK(close(owned) == 0);
    int oldmap = mapfd("uid_map", O_RDWR);
    CHECK(unshare(CLONE_NEWUSER) == 0);
    CHECK(getuid() == 65534 && geteuid() == 65534);
    CHECK(getgid() == 65534 && getegid() == 65534);
    // The fd opened before unshare still addresses the initial namespace.
    CHECK(write(oldmap, "0 1000 1\n", 9) == -1 && errno == EPERM);
    CHECK(close(oldmap) == 0);
    owned = open(path, O_RDWR);
    CHECK(owned >= 0); // inherited fsuid retains access while its map is empty
    struct stat st;
    CHECK(fstat(owned, &st) == 0 && st.st_uid == 65534 && st.st_gid == 65534);
    int fd = mapfd("uid_map", O_RDWR);
    CHECK(pwrite(fd, "42 1000 1\n", 10, 1) == -1 && errno == EINVAL);
    CHECK(write(fd, "0 0 1\n", 6) == -1 && errno == EPERM);
    CHECK(write(fd, "42 1000 1\n", 10) == 10);
    CHECK(write(fd, "42 1000 1\n", 10) == -1 && errno == EINVAL);
    CHECK(close(fd) == 0);
    mapwrite("setgroups", "deny\n");
    mapwrite("gid_map", "43 1000 1\n");
    CHECK(getuid() == 42 && geteuid() == 42 && getgid() == 43 && getegid() == 43);
    uid_t r, e, s;
    CHECK(getresuid(&r, &e, &s) == 0 && r == 42 && e == 42 && s == 42);
    CHECK(getresgid(&r, &e, &s) == 0 && r == 43 && e == 43 && s == 43);
    CHECK(getgroups(2, groups) == 2 && groups[0] == 43 && groups[1] == 65534);
    CHECK(setgroups(0, NULL) == -1 && errno == EPERM);
    CHECK(setuid(42) == 0 && setgid(43) == 0);
    CHECK(setuid(1000) == -1 && errno == EINVAL);
    CHECK(setgid(1000) == -1 && errno == EINVAL);
    CHECK(setfsuid(-1) == 42 && setfsgid(-1) == 43);
    CHECK(fstat(owned, &st) == 0 && st.st_uid == 42 && st.st_gid == 43);
    CHECK(fchown(owned, 42, 43) == 0);
    CHECK(fchown(owned, 1000, -1) == -1 && errno == EINVAL);
    static char child_stack[65536] __attribute__((aligned(16)));
    pid_t child = clone(child_userns, child_stack + sizeof(child_stack), CLONE_NEWUSER | SIGCHLD, NULL);
    CHECK(child > 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(getuid() == 42 && getgid() == 43);
    // Nested maps use parent-visible IDs and keep the same global identity.
    CHECK(unshare(CLONE_NEWUSER) == 0);
    CHECK(getuid() == 65534);
    mapwrite("uid_map", "7 42 1\n");
    mapwrite("gid_map", "8 43 1\n");
    CHECK(getuid() == 7 && getgid() == 8);
    fd = mapfd("uid_map", O_RDONLY);
    char buf[64] = {0};
    CHECK(read(fd, buf, sizeof(buf) - 1) > 0);
    unsigned inner, outer, count;
    CHECK(sscanf(buf, "%u %u %u", &inner, &outer, &count) == 3);
    CHECK(inner == 7 && outer == 42 && count == 1);
    CHECK(close(fd) == 0);
    CHECK(fstat(owned, &st) == 0 && st.st_uid == 7 && st.st_gid == 8);
    CHECK(close(owned) == 0 && unlink(path) == 0);
    puts("userns-ok");
    return 0;
}
