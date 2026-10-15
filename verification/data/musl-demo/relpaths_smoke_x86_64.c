// Relative-path *at coverage. After chdir into a writable dir, every
// filesystem mutation issued with a RELATIVE path (mkdir/open-create/
// rename/symlink/readlink/stat/unlink/rmdir, all AT_FDCWD under musl)
// must resolve against the cwd. This is what lets `mkdir foo`, `mv a b`,
// `rm foo`, `ln -s a b` work from a shell.
//
// execve resolves a relative pathname against the cwd too
// (`fs/exec.c::do_open_execat` walks from AT_FDCWD, i.e.
// `current->fs->pwd`): `cd /tmp; ./prog` must run /tmp/prog. That is
// covered for `./x`, `x/y`, `../x` and a bare `x` (execve never PATH
// searches) on each writable filesystem the boot has — after fork, after
// a CLONE_FS thread moved the shared cwd, and inside a chroot.
//
// getcwd must report a directory that exists in the caller's ROOT, not in
// the host's. OpenSSH's session process (and every task under a directly
// rooted PID 1) runs with a root other than "/"; its home directory exists
// only under that root. The chroot → fork → chdir → exec sequence below
// mirrors it and checks getcwd both before and after the exec.
//
// Success token "relpaths-ok".
//
// Build: see REGEN_relpaths_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHILD_OK 42

static void w(const char *m) { write(1, m, strlen(m)); }

static int fails;

static void fail(const char *what, const char *detail, int err) {
    char buf[512];
    snprintf(buf, sizeof buf, "relpaths-fail: %s [%s] errno=%d\n", what, detail, err);
    w(buf);
    fails++;
}

// Child mode, entered through the relative execs below. With an expected
// cwd it also checks getcwd from the freshly exec'd image — the moment a
// login shell prints "shell-init: error retrieving current directory".
static int child_main(int argc, char **argv) {
    if (argc >= 3) {
        char cwd[256];
        if (!getcwd(cwd, sizeof cwd)) {
            return 100 + (errno & 0x7f);
        }
        if (strcmp(cwd, argv[2]) != 0) {
            return 99;
        }
    }
    return CHILD_OK;
}

static int copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) {
        return -1;
    }
    int out = open(dst, O_CREAT | O_TRUNC | O_WRONLY, 0755);
    if (out < 0) {
        close(in);
        return -1;
    }
    char buf[8192];
    ssize_t n;
    int rc = 0;
    while ((n = read(in, buf, sizeof buf)) > 0) {
        if (write(out, buf, (size_t)n) != n) {
            rc = -1;
            break;
        }
    }
    if (n < 0) {
        rc = -1;
    }
    close(in);
    close(out);
    return rc;
}

static char self_path[512];

static int find_self(const char *argv0) {
    ssize_t n = readlink("/proc/self/exe", self_path, sizeof self_path - 1);
    if (n > 0) {
        self_path[n] = 0;
        if (access(self_path, R_OK) == 0) {
            return 0;
        }
    }
    if (argv0 && argv0[0] == '/') {
        snprintf(self_path, sizeof self_path, "%s", argv0);
        return 0;
    }
    return -1;
}

// Exec `rel` from cwd `dir` (NULL: inherit the caller's cwd) in a forked
// child. Returns the child's exit status, or -(errno) when execve failed.
static int exec_rel(const char *dir, const char *rel, const char *want_cwd) {
    int pfd[2];
    if (pipe2(pfd, O_CLOEXEC) != 0) {
        return -1000;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1001;
    }
    if (pid == 0) {
        close(pfd[0]);
        if (dir && chdir(dir) != 0) {
            int e = -1002;
            write(pfd[1], &e, sizeof e);
            _exit(1);
        }
        char *args[] = {(char *)rel, (char *)"--rp-child", (char *)want_cwd, NULL};
        char *env[] = {NULL};
        execve(rel, args, env);
        int e = -errno;
        write(pfd[1], &e, sizeof e);
        _exit(1);
    }
    close(pfd[1]);
    int e = 0;
    ssize_t got = read(pfd[0], &e, sizeof e);
    close(pfd[0]);
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) {
        return -1003;
    }
    if (got == (ssize_t)sizeof e) {
        return e;
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1004;
}

static void expect_runs(const char *dir, const char *rel, const char *want_cwd) {
    int r = exec_rel(dir, rel, want_cwd);
    if (r != CHILD_OK) {
        char d[300];
        snprintf(d, sizeof d, "cwd=%s exec=%s rc=%d", dir ? dir : "(inherited)", rel, r);
        fail("relative execve", d, r < 0 ? -r : 0);
    }
}

static void expect_errno(const char *dir, const char *rel, int want) {
    int r = exec_rel(dir, rel, NULL);
    if (r != -want) {
        char d[300];
        snprintf(d, sizeof d, "cwd=%s exec=%s rc=%d want=-%d", dir, rel, r, want);
        fail("relative execve errno", d, r < 0 ? -r : 0);
    }
}

// Lay out <base>/rpx/{rp_bin, sub/rp_bin2} and exec them relatively.
static int exec_suite(const char *base) {
    char top[256], sub[256], bin[300], bin2[300];
    snprintf(top, sizeof top, "%s/rpx", base);
    snprintf(sub, sizeof sub, "%s/rpx/sub", base);
    snprintf(bin, sizeof bin, "%s/rp_bin", top);
    snprintf(bin2, sizeof bin2, "%s/rp_bin2", sub);
    if (mkdir(top, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    if (mkdir(sub, 0755) != 0 && errno != EEXIST) {
        fail("mkdir", sub, errno);
        return 0;
    }
    if (copy_file(self_path, bin) != 0 || copy_file(self_path, bin2) != 0) {
        fail("copy self", top, errno);
        return 0;
    }
    expect_runs(top, "./rp_bin", top);
    expect_runs(top, "rp_bin", top);
    expect_runs(top, "sub/rp_bin2", top);
    expect_runs(top, "./sub/../rp_bin", top);
    expect_runs(sub, "../rp_bin", sub);
    expect_runs(sub, "./rp_bin2", sub);
    // A miss is ENOENT, which is what lets execvp-style callers move on.
    expect_errno(top, "./rp_nope", ENOENT);
    expect_errno(top, "sub/rp_nope", ENOENT);
    // `..` is walked from what precedes it: from a regular file that is
    // ENOTDIR (`link_path_walk`), not a lexical rewrite to ./rp_bin.
    expect_errno(top, "rp_bin/../rp_bin", ENOTDIR);
    // The absolute form still works from anywhere (control).
    expect_runs("/", bin, "/");
    unlink(bin2);
    unlink(bin);
    rmdir(sub);
    rmdir(top);
    return 0;
}

// CLONE_FS: every pthread shares one fs_struct, so a chdir in a thread
// moves the cwd the main thread's relative execve resolves against.
struct thr_arg {
    const char *dir;
    int rc;
};

static void *thr_chdir(void *p) {
    struct thr_arg *a = p;
    a->rc = chdir(a->dir);
    return NULL;
}

static int thread_chdir(const char *dir) {
    pthread_t t;
    struct thr_arg a = {dir, -1};
    if (pthread_create(&t, NULL, thr_chdir, &a) != 0) {
        return -1;
    }
    pthread_join(t, NULL);
    return a.rc;
}

static void thread_suite(const char *base) {
    char top[256], sub[256], bin[300];
    snprintf(top, sizeof top, "%s/rpt", base);
    snprintf(sub, sizeof sub, "%s/rpt/sub", base);
    snprintf(bin, sizeof bin, "%s/rp_bin", top);
    if (mkdir(top, 0755) != 0 || mkdir(sub, 0755) != 0 || copy_file(self_path, bin) != 0) {
        fail("thread suite setup", top, errno);
        return;
    }
    char saved[256];
    if (!getcwd(saved, sizeof saved)) {
        fail("getcwd before thread suite", base, errno);
        return;
    }
    if (thread_chdir(sub) != 0) {
        fail("chdir in a CLONE_FS thread", sub, errno);
        return;
    }
    char cwd[256];
    if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, sub) != 0) {
        fail("main thread getcwd after thread chdir", sub, errno);
    }
    expect_runs(NULL, "../rp_bin", sub);
    if (thread_chdir("..") != 0) {
        fail("relative chdir in a CLONE_FS thread", top, errno);
    }
    if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, top) != 0) {
        fail("main thread getcwd after thread chdir ..", top, errno);
    }
    expect_runs(NULL, "./rp_bin", top);
    expect_runs(NULL, "sub/../rp_bin", top);
    chdir(saved);
    unlink(bin);
    rmdir(sub);
    rmdir(top);
}

// The privsep-like sequence: a process under a root other than "/" chdirs
// to a directory that exists only inside that root, forks, execs a program
// relatively, and the new image asks getcwd where it is.
static void chroot_suite(const char *base) {
    char jail[256], home[300], lib[300], bin[350], ld[350];
    snprintf(jail, sizeof jail, "%s/rpjail", base);
    snprintf(home, sizeof home, "%s/home", jail);
    snprintf(lib, sizeof lib, "%s/lib", jail);
    const char *ldname = "/lib/ld-musl-x86_64.so.1";
    if (mkdir(jail, 0755) != 0 || mkdir(home, 0755) != 0 || mkdir(lib, 0755) != 0) {
        fail("jail setup", jail, errno);
        return;
    }
    snprintf(home, sizeof home, "%s/home/rpuser", jail);
    if (mkdir(home, 0755) != 0) {
        fail("jail setup", home, errno);
        return;
    }
    snprintf(bin, sizeof bin, "%s/rp_bin", home);
    snprintf(ld, sizeof ld, "%s%s", jail, ldname);
    if (copy_file(self_path, bin) != 0) {
        fail("jail copy self", bin, errno);
        return;
    }
    // Dynamic smokes need their loader inside the root (PT_INTERP resolves
    // under it); a static build has none and does not care.
    if (access(ldname, R_OK) == 0 && copy_file(ldname, ld) != 0) {
        fail("jail copy loader", ld, errno);
        return;
    }
    pid_t pid = fork();
    if (pid < 0) {
        fail("fork", "chroot suite", errno);
        return;
    }
    if (pid == 0) {
        fails = 0;
        if (chroot(jail) != 0) {
            fail("chroot", jail, errno);
            _exit(1);
        }
        // Like OpenSSH: the root changes first, the cwd follows separately.
        if (chdir("/") != 0) {
            fail("chdir / in jail", jail, errno);
            _exit(1);
        }
        char cwd[256];
        if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, "/") != 0) {
            fail("getcwd at jail root", cwd, errno);
        }
        pid_t gc = fork();
        if (gc == 0) {
            fails = 0;
            if (chdir("/home/rpuser") != 0) {
                fail("chdir to jailed home", "/home/rpuser", errno);
                _exit(1);
            }
            if (!getcwd(cwd, sizeof cwd)) {
                fail("getcwd in jailed home (only exists under the root)", "/home/rpuser", errno);
            } else if (strcmp(cwd, "/home/rpuser") != 0) {
                fail("getcwd in jailed home reported", cwd, 0);
            }
            expect_runs(NULL, "./rp_bin", "/home/rpuser");
            expect_runs(NULL, "rp_bin", "/home/rpuser");
            expect_runs("/home", "rpuser/rp_bin", "/home");
            expect_runs("/home/rpuser", "../rpuser/rp_bin", "/home/rpuser");
            // A CLONE_FS thread under the same root.
            if (thread_chdir("/home") != 0) {
                fail("thread chdir in jail", "/home", errno);
            }
            if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, "/home") != 0) {
                fail("getcwd after jailed thread chdir", "/home", errno);
            }
            expect_runs(NULL, "rpuser/rp_bin", "/home");
            _exit(fails ? 1 : 0);
        }
        int st = 0;
        if (gc < 0 || waitpid(gc, &st, 0) != gc || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            fail("jailed grandchild", "see above", 0);
        }
        _exit(fails ? 1 : 0);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        fail("jailed child", "see above", 0);
    }
    unlink(ld);
    unlink(bin);
    rmdir(home);
    snprintf(home, sizeof home, "%s/home", jail);
    rmdir(home);
    rmdir(lib);
    rmdir(jail);
}

static int at_mutations(void) {
    if (chdir("/dev/shm") != 0) {
        w("relpaths-fail: chdir\n");
        return 1;
    }
    if (mkdir("rpdir", 0755) != 0) {
        w("relpaths-fail: mkdir\n");
        return 1;
    }
    int fd = open("rpdir/a.txt", O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        w("relpaths-fail: create\n");
        return 1;
    }
    write(fd, "hi", 2);
    close(fd);
    if (rename("rpdir/a.txt", "rpdir/b.txt") != 0) {
        w("relpaths-fail: rename\n");
        return 1;
    }
    // relative stat must find the renamed file
    struct stat st;
    if (stat("rpdir/b.txt", &st) != 0) {
        w("relpaths-fail: stat\n");
        return 1;
    }
    if (unlink("rpdir/b.txt") != 0) {
        w("relpaths-fail: unlink\n");
        return 1;
    }
    if (rmdir("rpdir") != 0) {
        w("relpaths-fail: rmdir\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--rp-child") == 0) {
        return child_main(argc, argv);
    }
    if (at_mutations() != 0) {
        return 1;
    }
    if (find_self(argc > 0 ? argv[0] : NULL) != 0) {
        w("relpaths-fail: cannot locate own image\n");
        return 1;
    }
    // /tmp and /dev/shm are separate tmpfs-style mounts. RELPATHS_BASE
    // adds a directory on the root filesystem (the VM's root overlay); on
    // NARF the boot root is writable, so "/rproot" is tried as well.
    const char *bases[] = {"/tmp", "/dev/shm", getenv("RELPATHS_BASE"), "/rproot"};
    int ran = 0;
    for (unsigned i = 0; i < sizeof bases / sizeof bases[0]; i++) {
        const char *b = bases[i];
        if (!b) {
            continue;
        }
        if (strcmp(b, "/rproot") == 0 && mkdir(b, 0755) != 0 && errno != EEXIST) {
            char d[128];
            snprintf(d, sizeof d, "relpaths: skip %s (mkdir errno=%d)\n", b, errno);
            w(d);
            continue;
        }
        struct stat st;
        if (stat(b, &st) != 0 || !S_ISDIR(st.st_mode)) {
            continue;
        }
        if (exec_suite(b) != 0) {
            char d[128];
            snprintf(d, sizeof d, "relpaths: skip %s (not writable, errno=%d)\n", b, errno);
            w(d);
            continue;
        }
        thread_suite(b);
        chroot_suite(b);
        ran++;
        if (strcmp(b, "/rproot") == 0) {
            rmdir(b);
        }
    }
    if (ran < 2) {
        fail("too few writable bases", "need /tmp and /dev/shm", 0);
    }
    if (fails) {
        return 1;
    }
    w("relpaths-ok\n");
    return 0;
}
