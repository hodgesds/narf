// Native load generators for the QEMU soak (run-soak.sh builds this static).
//
// What a shell or Python cannot do: several threads of ONE process inside
// file reads, directory walks and file-mapping page faults at the same
// time, and a parent that SIGKILLs children a few milliseconds into those
// operations, thousands of times.
//
//   soak-native killstorm <secs> <slots> <bigfile> <tree> <scratch> <hbfile>
//       Keep <slots> children alive, each in one file operation loop
//       (pread, small-file reads, pwrite, append+fsync, shared and private
//       file mappings, getdents, renames, four threads of those, execve),
//       and SIGKILL each after 0-1000 ms. A child that is not gone 20 s
//       after its SIGKILL is reported as UNKILLABLE.
//   soak-native shared <secs> <procs> <threads> <dir> <hbfile>
//       Keep <procs> processes alive, each with <threads> threads working on
//       the SAME six files of <dir>: pwrite, append+fsync, pread, shared and
//       private mappings faulted while other threads write, truncate, rename
//       over and unlink the mapped files, and fork+exec / posix_spawn from the
//       threaded parent. Each process lives 0.2-4 s and then exits from one
//       thread or is SIGKILLed, with its siblings mid-fault and mid-write.
//   soak-native dirtyexit <mib> <file> <exit|kill> <tree>
//       One process maps <file> MAP_SHARED, dirties <mib> MiB of it and
//       exits without msync (or is SIGKILLed). Reports how long the exit
//       took to reap, for how long afterwards some CPU stayed 90% or more
//       busy, and the worst
//       stat() and fork+exec latency another thread saw meanwhile.
//   soak-native forkparent <secs> <dirty-mib> <forks-per-sec> <file> <hbfile>
//       One long-lived process keeps <dirty-mib> MiB of a MAP_SHARED mapping
//       of <file> dirty (a thread rewrites every page, over and over) and
//       forks a child that execs /usr/bin/true at the given rate, without
//       waiting for the previous one. Reports, per child, how long fork()
//       took, how long the child needed from "about to exec" to "exec done",
//       and from there to reaped; the heartbeat carries the running maxima
//       and how many children are outstanding. With FORKPARENT_CLEAN=1 in
//       the environment the mapping is only read: every page is cached and
//       mapped, none is dirty.
//   soak-native munmapbig <mib> <file>
//       Map <mib> MiB of <file> shared, dirty every page and time munmap.
//   soak-native firsttouch <mib> <file>
//       Write <mib> MiB to <file>, drop it from the cache, map it shared and
//       read-only, and time the first touch of every page.
//   soak-native mapchurn <secs> <mib> <file>
//       Map <mib> MiB shared, dirty it, munmap, over and over.
//   soak-native durable <file> <mib> <exit|kill|msync|fsync|nosync> <seed>
//       Fill <mib> MiB of <file> with the pattern of <seed> through a shared
//       mapping and then: exit (munmap and exit, no sync), kill (SIGKILL with
//       the mapping still dirty), msync (msync MS_SYNC), fsync (munmap, then
//       fsync the descriptor), nosync (munmap and exit, like exit; used just
//       before a hard stop). Prints "durable: <file> <mode> done" when the
//       process has finished (for kill, the parent prints it once reaped).
//   soak-native verify <file> <mib> <seed>
//       Check the pattern through read(2) and through a fresh mapping.
//   soak-native integrity <secs> <dir> <files> <hbfile>
//       Keep a shadow of each of <files> files in <dir> and change them at
//       random through shared mappings and write(2), with msync, ftruncate
//       and re-mapping interleaved; verify ranges through read(2) and through
//       a fresh mapping. Any mismatch prints INTEGRITY-MISMATCH with file,
//       offset and both bytes. At the end each file is fsynced and its
//       length and FNV-1a hash printed as INTEGRITY-FINAL, for the host.
//   soak-native lookups <secs> <threads> <tree> <hbfile>
//       <threads> threads resolve paths under <tree> (stat, open, and a
//       fork+exec every 256 lookups); the heartbeat carries the slowest
//       single lookup of the last second.
//   soak-native mmapfault <secs> <threads> <bigfile> <hbfile>
//       <threads> threads touch random pages of one shared mapping and
//       drop ranges of it again.
//   soak-native readtree <secs> <threads> <tree> <hbfile>
//       <threads> threads read every file and directory under <tree>.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *g_big, *g_tree, *g_scratch;
static char **g_files, **g_dirs;
static size_t g_nfiles, g_ndirs;
static uint64_t g_deadline_ns = UINT64_MAX;
static volatile uint64_t g_ops;

static __thread uint64_t t_rng;

static void write_hb(const char *path, const char *text);

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t rnd(void) {
    if (t_rng == 0)
        t_rng = now_ns() ^ ((uint64_t)getpid() << 32) ^ (uintptr_t)&t_rng;
    t_rng ^= t_rng << 13;
    t_rng ^= t_rng >> 7;
    t_rng ^= t_rng << 17;
    return t_rng;
}

static int running(void) {
    __atomic_add_fetch(&g_ops, 1, __ATOMIC_RELAXED);
    return now_ns() < g_deadline_ns;
}

static int walk_cb(const char *path, const struct stat *sb, int type, struct FTW *ftw) {
    (void)sb;
    (void)ftw;
    if (type == FTW_F && g_nfiles < 40000)
        g_files[g_nfiles++] = strdup(path);
    else if (type == FTW_D && g_ndirs < 8000)
        g_dirs[g_ndirs++] = strdup(path);
    return 0;
}

static void collect_tree(void) {
    g_files = calloc(40000, sizeof(char *));
    g_dirs = calloc(8000, sizeof(char *));
    nftw(g_tree, walk_cb, 32, FTW_PHYS);
    if (g_nfiles == 0 || g_ndirs == 0) {
        fprintf(stderr, "soak-native: no files under %s\n", g_tree);
        exit(2);
    }
}

static off_t file_size(int fd) {
    struct stat st;
    return fstat(fd, &st) == 0 ? st.st_size : 0;
}

// ── operation loops ─────────────────────────────────────────────────

static void op_pread(void) {
    int fd = open(g_big, O_RDONLY);
    off_t size = file_size(fd);
    char *buf = malloc(1 << 20);
    if (fd < 0 || size < (2 << 20))
        return;
    while (running()) {
        size_t len = 4096 + rnd() % ((1 << 20) - 4096);
        if (pread(fd, buf, len, (off_t)(rnd() % (uint64_t)(size - (off_t)len))) < 0)
            break;
    }
    close(fd);
    free(buf);
}

static void op_readfiles(void) {
    char *buf = malloc(65536);
    while (running()) {
        int fd = open(g_files[rnd() % g_nfiles], O_RDONLY);
        if (fd < 0)
            continue;
        while (read(fd, buf, 65536) > 0) {
        }
        close(fd);
    }
    free(buf);
}

static void scratch_path(char *out, size_t n, const char *kind) {
    snprintf(out, n, "%s/%s.%u", g_scratch, kind, (unsigned)(rnd() % 24));
}

static void op_pwrite(void) {
    char path[512];
    scratch_path(path, sizeof path, "w");
    int fd = open(path, O_CREAT | O_RDWR, 0644);
    char *buf = malloc(256 << 10);
    if (fd < 0)
        return;
    memset(buf, (int)(rnd() & 0xff), 256 << 10);
    while (running()) {
        size_t len = 4096 + rnd() % ((256 << 10) - 4096);
        if (pwrite(fd, buf, len, (off_t)(rnd() % (48u << 20))) < 0)
            break;
    }
    close(fd);
    free(buf);
}

static void op_appendsync(void) {
    char path[512];
    scratch_path(path, sizeof path, "a");
    int fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    char buf[65536];
    if (fd < 0)
        return;
    memset(buf, 'j', sizeof buf);
    while (running()) {
        if (write(fd, buf, 512 + rnd() % (sizeof buf - 512)) < 0)
            break;
        fsync(fd);
        if (file_size(fd) > (16 << 20))
            if (ftruncate(fd, 0) < 0)
                break;
    }
    close(fd);
}

static volatile unsigned char g_sink;

static void op_map_shared_read(void) {
    int fd = open(g_big, O_RDONLY);
    off_t size = file_size(fd);
    if (fd < 0 || size < (2 << 20))
        return;
    unsigned char *map = mmap(NULL, (size_t)size, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return;
    }
    uint64_t pages = (uint64_t)size / 4096, n = 0;
    while (running()) {
        g_sink += map[(rnd() % pages) * 4096];
        if ((++n & 0xfff) == 0) {
            // Drop a range again so later touches fault instead of hitting PTEs.
            uint64_t start = (rnd() % pages) & ~0xfffull;
            uint64_t len = pages - start < 4096 ? pages - start : 4096;
            madvise(map + start * 4096, len * 4096, MADV_DONTNEED);
            posix_fadvise(fd, (off_t)(start * 4096), (off_t)(len * 4096), POSIX_FADV_DONTNEED);
        }
    }
    munmap(map, (size_t)size);
    close(fd);
}

static void op_map_private_write(void) {
    int fd = open(g_big, O_RDONLY);
    off_t size = file_size(fd);
    size_t window = 64u << 20;
    if (fd < 0 || size < (off_t)window * 2)
        return;
    while (running()) {
        off_t off = (off_t)((rnd() % (uint64_t)(size - (off_t)window)) & ~0xfffull);
        unsigned char *map = mmap(NULL, window, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, off);
        if (map == MAP_FAILED)
            break;
        // Bounded: 2048 private copies, then the mapping goes away.
        for (int i = 0; i < 2048 && running(); i++)
            map[(rnd() % (window / 4096)) * 4096] = (unsigned char)i;
        munmap(map, window);
    }
    close(fd);
}

static void op_map_shared_write(void) {
    char path[512];
    scratch_path(path, sizeof path, "m");
    size_t len = 32u << 20;
    int fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd < 0 || ftruncate(fd, (off_t)len) < 0)
        return;
    unsigned char *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return;
    }
    uint64_t n = 0;
    while (running()) {
        map[(rnd() % (len / 4096)) * 4096 + (rnd() & 0xfff)] = (unsigned char)n;
        if ((++n & 0x3ff) == 0)
            msync(map, len, (n & 0x400) ? MS_ASYNC : MS_SYNC);
    }
    munmap(map, len);
    close(fd);
}

static void op_getdents(void) {
    while (running()) {
        const char *path = g_dirs[rnd() % g_ndirs];
        DIR *d = opendir(path);
        if (!d)
            continue;
        struct dirent *e;
        struct stat st;
        while ((e = readdir(d)) != NULL)
            fstatat(dirfd(d), e->d_name, &st, AT_SYMLINK_NOFOLLOW);
        closedir(d);
    }
}

static void op_namespace(void) {
    char dir[512], a[600], b[600];
    scratch_path(dir, sizeof dir, "ns");
    mkdir(dir, 0755);
    while (running()) {
        unsigned k = (unsigned)(rnd() % 64);
        snprintf(a, sizeof a, "%s/f%u", dir, k);
        snprintf(b, sizeof b, "%s/g%u", dir, (unsigned)(rnd() % 64));
        int fd = open(a, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            if (write(fd, a, strlen(a)) < 0) {
            }
            close(fd);
        }
        rename(a, b);
        if ((rnd() & 3) == 0)
            unlink(b);
    }
}

// ── one process, many threads, the same files ───────────────────────

#define SHARED_FILES 6
#define SHARED_MAX (16u << 20)
static int g_threads = 12;
static __thread sigjmp_buf t_jmp;
static __thread volatile int t_jmp_armed;

// A page of a mapping whose file was truncated under it raises SIGBUS.
static void on_sigbus(int sig) {
    (void)sig;
    if (t_jmp_armed)
        siglongjmp(t_jmp, 1);
    _exit(5);
}

static void shared_path(char *out, size_t n) {
    snprintf(out, n, "%s/s%u.dat", g_scratch, (unsigned)(rnd() % SHARED_FILES));
}

static int shared_open(int flags) {
    char path[512];
    shared_path(path, sizeof path);
    return open(path, O_CREAT | flags, 0644);
}

static void *sh_writer(void *arg) {
    (void)arg;
    char *buf = malloc(128 << 10);
    memset(buf, (int)(rnd() & 0xff), 128 << 10);
    for (uint64_t n = 1;; n++) {
        int fd = shared_open(O_RDWR);
        if (fd < 0)
            continue;
        for (int i = 0; i < 64; i++) {
            size_t len = 4096 + rnd() % ((128 << 10) - 4096);
            if (pwrite(fd, buf, len, (off_t)(rnd() % (SHARED_MAX - (128 << 10)))) < 0)
                break;
            if ((i & 7) == 7)
                (n & 1) ? fsync(fd) : fdatasync(fd);
        }
        close(fd);
    }
    return NULL;
}

static void *sh_appender(void *arg) {
    (void)arg;
    char buf[65536];
    memset(buf, 'a', sizeof buf);
    for (;;) {
        int fd = shared_open(O_WRONLY | O_APPEND);
        if (fd < 0)
            continue;
        for (int i = 0; i < 32; i++) {
            if (write(fd, buf, 1024 + rnd() % (sizeof buf - 1024)) < 0)
                break;
            if ((i & 3) == 3)
                fsync(fd);
            if (file_size(fd) > (off_t)SHARED_MAX + (8 << 20))
                if (ftruncate(fd, 1 << 20) < 0)
                    break;
        }
        close(fd);
    }
    return NULL;
}

static void *sh_reader(void *arg) {
    (void)arg;
    char *buf = malloc(256 << 10);
    for (;;) {
        int fd = shared_open(O_RDONLY);
        if (fd < 0)
            continue;
        for (int i = 0; i < 64; i++)
            if (pread(fd, buf, 4096 + rnd() % (252 << 10), (off_t)(rnd() % SHARED_MAX)) < 0)
                break;
        lseek(fd, 0, SEEK_SET);
        while (read(fd, buf, 256 << 10) > 0) {
        }
        close(fd);
    }
    return NULL;
}

static void *sh_mapper(void *arg) {
    volatile int private_copy = arg != NULL;
    for (;;) {
        int fd = shared_open(O_RDWR);
        if (fd < 0)
            continue;
        off_t size = file_size(fd);
        if (size < 8192) {
            if (ftruncate(fd, 1 << 20) < 0) {
            }
            size = file_size(fd);
        }
        volatile size_t len = size > (off_t)SHARED_MAX ? SHARED_MAX : (size_t)size & ~0xfffull;
        if (len == 0) {
            close(fd);
            continue;
        }
        unsigned char *volatile map = mmap(NULL, len, PROT_READ | PROT_WRITE,
                                  private_copy ? MAP_PRIVATE : MAP_SHARED, fd, 0);
        // The mapping outlives the descriptor, and the name, as it does for
        // a memory-mapped database file that is replaced by rename.
        close(fd);
        if (map == MAP_FAILED)
            continue;
        for (volatile int i = 0; i < 3000; i++) {
            t_jmp_armed = 1;
            if (sigsetjmp(t_jmp, 1) == 0) {
                size_t at = (rnd() % (len / 4096)) * 4096 + (rnd() & 0xfff);
                if (rnd() & 1)
                    map[at] = (unsigned char)i;
                else
                    g_sink += map[at];
            }
            t_jmp_armed = 0;
            if (!private_copy && (i % 500) == 499)
                msync(map, len, (i & 512) ? MS_SYNC : MS_ASYNC);
        }
        munmap(map, len);
    }
    return NULL;
}

static void *sh_truncator(void *arg) {
    (void)arg;
    for (;;) {
        int fd = shared_open(O_RDWR);
        if (fd >= 0) {
            if (ftruncate(fd, (off_t)(rnd() % SHARED_MAX)) < 0) {
            }
            close(fd);
        }
        usleep(5000 + (useconds_t)(rnd() % 45000));
    }
    return NULL;
}

static void *sh_renamer(void *arg) {
    (void)arg;
    char tmp[512], dst[512];
    char *buf = malloc(1 << 20);
    memset(buf, 'r', 1 << 20);
    for (uint64_t n = 0;; n++) {
        snprintf(tmp, sizeof tmp, "%s/tmp.%d.%llu", g_scratch, (int)getpid(),
                 (unsigned long long)(n & 3));
        shared_path(dst, sizeof dst);
        int fd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            if (write(fd, buf, (64 << 10) + rnd() % ((1 << 20) - (64 << 10))) < 0) {
            }
            fsync(fd);
            close(fd);
            rename(tmp, dst);
        }
        if ((n & 7) == 7) {
            shared_path(dst, sizeof dst);
            unlink(dst);
        }
        usleep(2000 + (useconds_t)(rnd() % 20000));
    }
    return NULL;
}

extern char **environ;

static void *sh_forker(void *arg) {
    (void)arg;
    char *const argv[] = {"true", NULL};
    for (uint64_t n = 0;; n++) {
        pid_t pid;
        if (n & 1) {
            pid = fork();
            if (pid == 0) {
                execv("/usr/bin/true", argv);
                _exit(127);
            }
        } else if (posix_spawn(&pid, "/usr/bin/true", NULL, NULL, argv, environ) != 0) {
            pid = -1;
        }
        if (pid > 0)
            waitpid(pid, NULL, 0);
        usleep(2000 + (useconds_t)(rnd() % 18000));
    }
    return NULL;
}

static void *sh_exit(void *arg) {
    usleep((useconds_t)(uintptr_t)arg);
    // exit_group from one thread while the others are inside the kernel.
    _exit(0);
    return NULL;
}

static void op_shared(void) {
    static void *(*const ROLES[])(void *) = {sh_writer,   sh_mapper, sh_reader,    sh_mapper,
                                             sh_appender, sh_writer, sh_truncator, sh_renamer,
                                             sh_forker,   sh_mapper, sh_reader,    sh_writer};
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigbus;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGBUS, &sa, NULL);
    pthread_t t;
    int mappers = 0;
    for (int i = 0; i < g_threads; i++) {
        void *(*role)(void *) = ROLES[i % (int)(sizeof ROLES / sizeof *ROLES)];
        // Every third mapper keeps private copies.
        void *arg = role == sh_mapper && (mappers++ % 3) == 2 ? (void *)1 : NULL;
        pthread_create(&t, NULL, role, arg);
    }
    // Half of these processes end themselves; the supervisor kills the rest.
    if (rnd() & 1)
        pthread_create(&t, NULL, sh_exit, (void *)(uintptr_t)(200000 + rnd() % 3800000));
    for (;;)
        pause();
}

typedef void (*op_fn)(void);
static const op_fn THREAD_OPS[] = {op_pread,           op_readfiles,          op_pwrite,
                                   op_map_shared_read, op_map_private_write, op_getdents};

static void *thread_main(void *arg) {
    ((op_fn)arg)();
    return NULL;
}

static void op_threads(void) {
    pthread_t t[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, thread_main,
                       (void *)THREAD_OPS[rnd() % (sizeof THREAD_OPS / sizeof *THREAD_OPS)]);
    for (int i = 0; i < 4; i++)
        pthread_join(t[i], NULL);
}

static void op_exec(void) {
    int null = open("/dev/null", O_WRONLY);
    dup2(null, 1);
    dup2(null, 2);
    switch (rnd() % 5) {
    case 0:
        execl("/usr/bin/sha256sum", "sha256sum", g_big, (char *)NULL);
        break;
    case 1:
        execl("/usr/bin/rg", "rg", "-c", "unsafe", g_tree, (char *)NULL);
        break;
    case 2:
        execl("/usr/bin/git", "git", "-c", "safe.directory=*", "-C", g_tree, "status", "--short",
              (char *)NULL);
        break;
    case 3:
        execl("/usr/bin/python3", "python3", "-c", "import ssl, json, subprocess, socket",
              (char *)NULL);
        break;
    default:
        execl("/usr/bin/find", "find", g_tree, "-type", "f", "-size", "+1k", (char *)NULL);
    }
    _exit(127);
}

static const struct {
    const char *name;
    op_fn fn;
} MODES[] = {
    {"pread", op_pread},
    {"readfiles", op_readfiles},
    {"pwrite", op_pwrite},
    {"appendsync", op_appendsync},
    {"map-shared-read", op_map_shared_read},
    {"map-private-write", op_map_private_write},
    {"map-shared-write", op_map_shared_write},
    {"getdents", op_getdents},
    {"namespace", op_namespace},
    {"threads", op_threads},
    {"exec", op_exec},
    {"shared", op_shared},
};
#define NMODES (sizeof MODES / sizeof *MODES)
#define MODE_SHARED ((int)NMODES - 1)

// ── path lookups, timed ─────────────────────────────────────────────

static uint64_t g_lat_max_ns;

static void note_latency(uint64_t ns) {
    uint64_t seen = __atomic_load_n(&g_lat_max_ns, __ATOMIC_RELAXED);
    while (ns > seen &&
           !__atomic_compare_exchange_n(&g_lat_max_ns, &seen, ns, 0, __ATOMIC_RELAXED,
                                        __ATOMIC_RELAXED)) {
    }
}

static void spawn_true(void) {
    char *const argv[] = {"true", NULL};
    pid_t pid = fork();
    if (pid == 0) {
        execv("/usr/bin/true", argv);
        _exit(127);
    }
    if (pid > 0)
        waitpid(pid, NULL, 0);
}

static void op_lookup(void) {
    struct stat st;
    for (uint64_t n = 1; running(); n++) {
        const char *path = g_files[rnd() % g_nfiles];
        uint64_t t = now_ns();
        if (n & 1) {
            stat(path, &st);
        } else {
            int fd = open(path, O_RDONLY);
            if (fd >= 0)
                close(fd);
        }
        note_latency(now_ns() - t);
        if ((n & 255) == 0) {
            t = now_ns();
            spawn_true();
            note_latency(now_ns() - t);
        }
    }
}

// ── exit with dirty shared pages ────────────────────────────────────

#define MAX_CPUS 64

static int read_cpu_times(uint64_t *sys, uint64_t *total) {
    FILE *f = fopen("/proc/stat", "r");
    char line[512];
    int n = 0;
    if (!f)
        return 0;
    while (fgets(line, sizeof line, f) && n < MAX_CPUS) {
        unsigned cpu;
        unsigned long long v[8] = {0};
        if (sscanf(line, "cpu%u %llu %llu %llu %llu %llu %llu %llu %llu", &cpu, &v[0], &v[1],
                   &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) < 5)
            continue;
        // Busy time, whatever it is charged to: a kernel that runs work on
        // behalf of no task does not reliably call it system time.
        sys[n] = v[0] + v[1] + v[2] + v[5] + v[6] + v[7];
        total[n] = v[0] + v[1] + v[2] + v[3] + v[4] + v[5] + v[6] + v[7];
        n++;
    }
    fclose(f);
    return n;
}

struct latency {
    volatile int stop;
    uint64_t stat_max_ns, exec_max_ns, stat_n, exec_n;
};

static void *latency_thread(void *arg) {
    struct latency *l = arg;
    struct stat st;
    for (uint64_t n = 1; !l->stop; n++) {
        uint64_t t = now_ns(), d;
        stat(g_files[rnd() % g_nfiles], &st);
        d = now_ns() - t;
        if (d > l->stat_max_ns)
            l->stat_max_ns = d;
        l->stat_n++;
        if ((n % 10) == 0) {
            t = now_ns();
            spawn_true();
            d = now_ns() - t;
            if (d > l->exec_max_ns)
                l->exec_max_ns = d;
            l->exec_n++;
        }
        usleep(5000);
    }
    return NULL;
}

static int dirtyexit(size_t mib, const char *file, int kill_it) {
    // How long to keep watching after the reap; under other load the CPUs
    // never go quiet, so the caller bounds it.
    const char *window_env = getenv("DIRTYEXIT_WINDOW_MS");
    uint64_t window_ns = (window_env ? strtoull(window_env, NULL, 10) : 240000) * 1000000ull;
    int pfd[2];
    if (pipe(pfd) < 0)
        return 2;
    uint64_t t0 = now_ns();
    pid_t pid = fork();
    if (pid == 0) {
        size_t len = mib << 20;
        int fd = open(file, O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (fd < 0 || ftruncate(fd, (off_t)len) < 0)
            _exit(2);
        unsigned char *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (map == MAP_FAILED)
            _exit(3);
        for (size_t off = 0; off < len; off += 4096)
            memcpy(map + off, &off, sizeof off);
        if (write(pfd[1], "d", 1) != 1)
            _exit(4);
        if (kill_it)
            for (;;)
                pause();
        // No msync, no munmap: the dirty pages are the exit path's problem.
        _exit(0);
    }
    close(pfd[1]);
    char byte;
    if (read(pfd[0], &byte, 1) != 1) {
        printf("dirtyexit: mib=%zu the child failed before its pages were dirty\n", mib);
        waitpid(pid, NULL, 0);
        return 1;
    }
    uint64_t t_dirty = now_ns();
    struct latency lat = {0};
    pthread_t prober;
    pthread_create(&prober, NULL, latency_thread, &lat);
    uint64_t sys0[MAX_CPUS], tot0[MAX_CPUS], sys1[MAX_CPUS], tot1[MAX_CPUS];
    int ncpu = read_cpu_times(sys0, tot0);
    if (kill_it)
        kill(pid, SIGKILL);
    uint64_t t_end = now_ns();
    waitpid(pid, NULL, 0);
    uint64_t t_reaped = now_ns(), last_bound = 0;
    int max_bound = 0;
    for (;;) {
        // One-second samples: a burst of short processes on one CPU fills a
        // fifth of a second and is not a capture.
        usleep(1000000);
        uint64_t now = now_ns();
        int bound = 0;
        if (read_cpu_times(sys1, tot1) != ncpu)
            break;
        for (int c = 0; c < ncpu; c++) {
            uint64_t dt = tot1[c] - tot0[c], ds = sys1[c] - sys0[c];
            // A CPU whose counters stood still says nothing: an idle CPU
            // without a tick looks exactly like that.
            if (dt >= 50 && ds * 100 >= dt * 90)
                bound++;
            // Keep the baseline until enough ticks have accumulated.
            if (dt >= 50) {
                sys0[c] = sys1[c];
                tot0[c] = tot1[c];
            }
        }
        if (bound) {
            last_bound = now;
            if (bound > max_bound)
                max_bound = bound;
        }
        uint64_t quiet_since = last_bound > t_reaped ? last_bound : t_reaped;
        if (now - quiet_since > 3000000000ull || now - t_reaped > window_ns)
            break;
    }
    lat.stop = 1;
    pthread_join(prober, NULL);
    printf("dirtyexit: mib=%zu mode=%s dirty_ms=%llu reap_ms=%llu cpu_bound_ms=%llu "
           "cpus_bound_max=%d stat_max_ms=%llu exec_max_ms=%llu (stat n=%llu exec n=%llu)\n",
           mib, kill_it ? "kill" : "exit", (unsigned long long)((t_dirty - t0) / 1000000),
           (unsigned long long)((t_reaped - t_end) / 1000000),
           (unsigned long long)(last_bound > t_end ? (last_bound - t_end) / 1000000 : 0), max_bound,
           (unsigned long long)(lat.stat_max_ns / 1000000),
           (unsigned long long)(lat.exec_max_ns / 1000000), (unsigned long long)lat.stat_n,
           (unsigned long long)lat.exec_n);
    unlink(file);
    return 0;
}

// ── a parent with dirty shared pages that keeps forking ─────────────

static unsigned char *g_dirty_map;
static size_t g_dirty_len;
static volatile int g_dirty_stop, g_dirty_passes;

static void *dirtier_thread(void *arg) {
    if (arg) {
        // Clean variant: fault every page in once, write nothing.
        for (size_t off = 0; off < g_dirty_len; off += 4096)
            g_sink += g_dirty_map[off];
        return NULL;
    }
    for (uint64_t pass = 1; !g_dirty_stop; pass++) {
        for (size_t off = 0; off < g_dirty_len && !g_dirty_stop; off += 4096)
            memcpy(g_dirty_map + off, &pass, sizeof pass);
        g_dirty_passes = (int)pass;
        usleep(20000);
    }
    return NULL;
}

struct child {
    pid_t pid;
    int fd, stage;
    uint64_t forked, pre_exec, execed;
};

struct span {
    uint64_t n, sum, max;
};

static void span_add(struct span *s, uint64_t ns) {
    s->n++;
    s->sum += ns;
    if (ns > s->max)
        s->max = ns;
}

#define MS(ns) ((unsigned long long)((ns) / 1000000))
#define AVG(s) ((s).n ? MS((s).sum / (s).n) : 0ull)

static int forkparent(uint64_t secs, size_t mib, double rate, const char *file, const char *hb) {
    enum { MAX_CHILDREN = 64 };
    struct child kids[MAX_CHILDREN] = {0};
    struct span fork_s = {0}, exec_s = {0}, exit_s = {0};
    char *const argv[] = {"true", NULL};
    char line[512];
    g_dirty_len = mib << 20;
    int fd = open(file, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0 || ftruncate(fd, (off_t)g_dirty_len) < 0)
        return 2;
    g_dirty_map = mmap(NULL, g_dirty_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (g_dirty_map == MAP_FAILED)
        return 3;
    int clean = getenv("FORKPARENT_CLEAN") != NULL;
    pthread_t dirtier;
    pthread_create(&dirtier, NULL, dirtier_thread, clean ? (void *)1 : NULL);
    if (clean)
        pthread_join(dirtier, NULL);
    else
        // Every page is faulted in and dirty before the first fork.
        while (g_dirty_passes == 0)
            usleep(10000);
    uint64_t start = now_ns(), end = start + secs * 1000000000ull;
    uint64_t period = (uint64_t)(1e9 / rate), next_fork = start, next_hb = start;
    uint64_t forks = 0, skipped = 0;
    int live = 0, max_live = 0;
    for (;;) {
        uint64_t now = now_ns();
        if (now < end && now >= next_fork) {
            next_fork += period;
            int slot = -1;
            for (int i = 0; i < MAX_CHILDREN; i++)
                if (kids[i].pid == 0) {
                    slot = i;
                    break;
                }
            int pfd[2];
            if (slot < 0 || pipe2(pfd, O_CLOEXEC) < 0) {
                skipped++;
            } else {
                uint64_t t = now_ns();
                pid_t pid = fork();
                if (pid == 0) {
                    // The byte says "about to exec"; exec closes the pipe.
                    if (write(pfd[1], "x", 1) != 1)
                        _exit(126);
                    execv("/usr/bin/true", argv);
                    _exit(127);
                }
                close(pfd[1]);
                if (pid < 0) {
                    close(pfd[0]);
                    skipped++;
                } else {
                    uint64_t done = now_ns();
                    span_add(&fork_s, done - t);
                    fcntl(pfd[0], F_SETFL, O_NONBLOCK);
                    kids[slot] = (struct child){pid, pfd[0], 0, done, 0, 0};
                    forks++;
                    live++;
                    if (live > max_live)
                        max_live = live;
                }
            }
        }
        for (int i = 0; i < MAX_CHILDREN; i++) {
            struct child *k = &kids[i];
            char byte;
            if (k->pid == 0)
                continue;
            while (k->stage < 2) {
                ssize_t r = read(k->fd, &byte, 1);
                if (r == 1) {
                    k->stage = 1;
                    k->pre_exec = now_ns();
                } else if (r == 0) {
                    k->stage = 2;
                    k->execed = now_ns();
                    span_add(&exec_s, k->execed - (k->pre_exec ? k->pre_exec : k->forked));
                } else {
                    break;
                }
            }
            if (waitpid(k->pid, NULL, WNOHANG) == k->pid) {
                uint64_t t = now_ns();
                if (k->stage < 2)
                    span_add(&exec_s, t - (k->pre_exec ? k->pre_exec : k->forked));
                span_add(&exit_s, t - (k->execed ? k->execed : k->forked));
                close(k->fd);
                k->pid = 0;
                live--;
            }
        }
        if (now >= next_hb) {
            next_hb = now + 1000000000ull;
            snprintf(line, sizeof line,
                     "forks=%llu live=%d fork_ms_max=%llu exec_ms_max=%llu exit_ms_max=%llu\n",
                     (unsigned long long)forks, live, MS(fork_s.max), MS(exec_s.max),
                     MS(exit_s.max));
            write_hb(hb, line);
        }
        // After the fork window, wait for the stragglers (up to ten minutes).
        if (now >= end && (live == 0 || now > end + 600000000000ull))
            break;
        usleep(1000);
    }
    uint64_t finished = now_ns();
    g_dirty_stop = 1;
    if (!clean)
        pthread_join(dirtier, NULL);
    printf("forkparent: %s_mib=%zu rate=%.1f/s window_s=%llu forks=%llu skipped=%llu "
           "max_outstanding=%d still_outstanding=%d drain_ms=%llu | fork_ms avg=%llu max=%llu | "
           "exec_ms avg=%llu max=%llu | exit_ms avg=%llu max=%llu\n",
           clean ? "clean" : "dirty", mib, rate, (unsigned long long)secs,
           (unsigned long long)forks,
           (unsigned long long)skipped, max_live, live, MS(finished > end ? finished - end : 0),
           AVG(fork_s), MS(fork_s.max), AVG(exec_s), MS(exec_s.max), AVG(exit_s), MS(exit_s.max));
    // No munmap: the parent dies with its pages dirty, like the processes
    // this stands in for. Its teardown is the last thing the round costs.
    fflush(stdout);
    unlink(file);
    _exit(0);
}

// ── durability and integrity ────────────────────────────────────────

// The pattern word at byte offset `off` of a file written with `seed`.
static uint64_t pattern_word(uint64_t seed, uint64_t off) {
    uint64_t x = seed * 0x9E3779B97F4A7C15ull ^ off;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return x;
}

static int munmapbig(size_t mib, const char *file) {
    size_t len = mib << 20;
    int fd = open(file, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0 || ftruncate(fd, (off_t)len) < 0)
        return 2;
    unsigned char *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED)
        return 3;
    uint64_t t0 = now_ns();
    for (size_t off = 0; off < len; off += 4096)
        memcpy(map + off, &off, sizeof off);
    uint64_t t1 = now_ns();
    munmap(map, len);
    uint64_t t2 = now_ns();
    close(fd);
    uint64_t t3 = now_ns();
    printf("munmapbig: mib=%zu dirty_ms=%llu munmap_ms=%llu close_ms=%llu\n", mib, MS(t1 - t0),
           MS(t2 - t1), MS(t3 - t2));
    return 0;
}

static int firsttouch(size_t mib, const char *file) {
    size_t len = mib << 20;
    char *buf = malloc(1 << 20);
    memset(buf, 'f', 1 << 20);
    int fd = open(file, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0)
        return 2;
    for (size_t i = 0; i < mib; i++)
        if (write(fd, buf, 1 << 20) != 1 << 20)
            return 3;
    fsync(fd);
    posix_fadvise(fd, 0, (off_t)len, POSIX_FADV_DONTNEED);
    unsigned char *map = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED)
        return 4;
    uint64_t t0 = now_ns(), worst = 0;
    for (size_t off = 0; off < len; off += 4096) {
        uint64_t t = now_ns();
        g_sink += map[off];
        t = now_ns() - t;
        if (t > worst)
            worst = t;
    }
    uint64_t t1 = now_ns();
    munmap(map, len);
    close(fd);
    unlink(file);
    printf("firsttouch: mib=%zu pages=%zu total_ms=%llu per_page_us=%llu worst_ms=%llu\n", mib,
           len / 4096, MS(t1 - t0), (unsigned long long)((t1 - t0) / 1000 / (len / 4096)),
           MS(worst));
    return 0;
}

static int mapchurn(uint64_t secs, size_t mib, const char *file) {
    size_t len = mib << 20;
    uint64_t end = now_ns() + secs * 1000000000ull, rounds = 0, worst_map = 0, worst_unmap = 0;
    int fd = open(file, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0 || ftruncate(fd, (off_t)len) < 0)
        return 2;
    while (now_ns() < end) {
        uint64_t t = now_ns();
        unsigned char *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        t = now_ns() - t;
        if (t > worst_map)
            worst_map = t;
        if (map == MAP_FAILED)
            return 3;
        for (size_t off = 0; off < len; off += 4096)
            map[off] = (unsigned char)rounds;
        t = now_ns();
        munmap(map, len);
        t = now_ns() - t;
        if (t > worst_unmap)
            worst_unmap = t;
        rounds++;
    }
    close(fd);
    unlink(file);
    printf("mapchurn: mib=%zu rounds=%llu worst_mmap_ms=%llu worst_munmap_ms=%llu\n", mib,
           (unsigned long long)rounds, MS(worst_map), MS(worst_unmap));
    return 0;
}

static int durable(const char *file, size_t mib, const char *mode, uint64_t seed) {
    size_t len = mib << 20;
    int kill_it = strcmp(mode, "kill") == 0;
    int pfd[2];
    if (pipe(pfd) < 0)
        return 2;
    pid_t pid = fork();
    if (pid == 0) {
        int fd = open(file, O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (fd < 0 || ftruncate(fd, (off_t)len) < 0)
            _exit(2);
        uint64_t *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (map == MAP_FAILED)
            _exit(3);
        for (size_t i = 0; i < len / 8; i++)
            map[i] = pattern_word(seed, i * 8);
        if (strcmp(mode, "msync") == 0) {
            if (msync(map, len, MS_SYNC) != 0)
                _exit(4);
        }
        if (kill_it) {
            if (write(pfd[1], "d", 1) != 1)
                _exit(5);
            for (;;)
                pause();
        }
        if (strcmp(mode, "msync") != 0)
            munmap(map, len);
        if (strcmp(mode, "fsync") == 0 && fsync(fd) != 0)
            _exit(6);
        _exit(0);
    }
    close(pfd[1]);
    if (kill_it) {
        char byte;
        if (read(pfd[0], &byte, 1) != 1)
            return 7;
        kill(pid, SIGKILL);
    }
    int status;
    waitpid(pid, &status, 0);
    if (!kill_it && !(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
        printf("durable: %s %s FAILED status=%#x\n", file, mode, status);
        return 1;
    }
    printf("durable: %s %s done seed=%llu mib=%zu\n", file, mode, (unsigned long long)seed, mib);
    return 0;
}

static int verify(const char *file, size_t mib, uint64_t seed) {
    size_t len = mib << 20, bad_read = 0, bad_map = 0, first = (size_t)-1;
    int fd = open(file, O_RDONLY);
    if (fd < 0) {
        printf("verify: %s cannot open\n", file);
        return 1;
    }
    uint64_t *buf = malloc(1 << 20);
    for (size_t off = 0; off < len; off += 1 << 20) {
        ssize_t n = pread(fd, buf, 1 << 20, (off_t)off);
        for (ssize_t i = 0; i < n / 8; i++)
            if (buf[i] != pattern_word(seed, off + (size_t)i * 8)) {
                if (first == (size_t)-1)
                    first = off + (size_t)i * 8;
                bad_read++;
            }
        if (n < (1 << 20))
            bad_read += (size_t)((1 << 20) - (n < 0 ? 0 : n)) / 8;
    }
    uint64_t *map = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
    if (map != MAP_FAILED) {
        for (size_t i = 0; i < len / 8; i++)
            if (map[i] != pattern_word(seed, i * 8))
                bad_map++;
        munmap(map, len);
    }
    close(fd);
    printf("verify: %s mib=%zu bad_words_read=%zu bad_words_map=%zu first_bad=%lld\n", file, mib,
           bad_read, bad_map, first == (size_t)-1 ? -1ll : (long long)first);
    return bad_read || bad_map;
}

#define INTEG_MAX (4u << 20)

struct integ_file {
    char path[512];
    unsigned char *shadow;
    size_t len;
    int fd;
};

static uint64_t fnv1a(const unsigned char *p, size_t n) {
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

static uint64_t g_integ_mismatch, g_integ_ops, g_slow_map, g_slow_unmap, g_worst_map, g_worst_unmap;

static void integ_check(struct integ_file *f, const unsigned char *got, size_t off, size_t n,
                        const char *how) {
    for (size_t i = 0; i < n; i++) {
        unsigned char want = off + i < f->len ? f->shadow[off + i] : 0;
        if (got[i] != want) {
            g_integ_mismatch++;
            if (g_integ_mismatch <= 20)
                fprintf(stderr,
                        "INTEGRITY-MISMATCH %s via %s offset %zu expected %#x got %#x (len %zu)\n",
                        f->path, how, off + i, want, got[i], f->len);
            return;
        }
    }
}

static void integ_note_time(uint64_t t, int unmap) {
    uint64_t *worst = unmap ? &g_worst_unmap : &g_worst_map;
    if (t > *worst)
        *worst = t;
    if (t > 100000000ull)
        (*(unmap ? &g_slow_unmap : &g_slow_map))++;
}

static int integrity(uint64_t secs, const char *dir, int nfiles, const char *hb) {
    struct integ_file *files = calloc((size_t)nfiles, sizeof *files);
    unsigned char *tmp = malloc(INTEG_MAX);
    char line[256];
    mkdir(dir, 0755);
    for (int i = 0; i < nfiles; i++) {
        struct integ_file *f = &files[i];
        snprintf(f->path, sizeof f->path, "%s/i%d.dat", dir, i);
        f->shadow = calloc(1, INTEG_MAX);
        f->fd = open(f->path, O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (f->fd < 0)
            return 2;
        f->len = 0;
    }
    uint64_t end = now_ns() + secs * 1000000000ull, next_hb = 0;
    while (now_ns() < end) {
        struct integ_file *f = &files[rnd() % (uint64_t)nfiles];
        unsigned op = (unsigned)(rnd() % 10);
        size_t off = (size_t)(rnd() % INTEG_MAX) & ~7ull;
        size_t n = 1 + (size_t)(rnd() % (256 << 10));
        if (off + n > INTEG_MAX)
            n = INTEG_MAX - off;
        unsigned char val = (unsigned char)(rnd() | 1);
        g_integ_ops++;
        if (op < 3) {
            // Store through a shared mapping of the page range, growing the
            // file first if needed.
            if (off + n > f->len) {
                if (ftruncate(f->fd, (off_t)(off + n)) != 0)
                    continue;
                f->len = off + n;
            }
            size_t base = off & ~4095ull, mlen = ((off + n + 4095) & ~4095ull) - base;
            if (base + mlen > ((f->len + 4095) & ~4095ull))
                mlen = ((f->len + 4095) & ~4095ull) - base;
            uint64_t t = now_ns();
            unsigned char *map = mmap(NULL, mlen, PROT_READ | PROT_WRITE, MAP_SHARED, f->fd,
                                      (off_t)base);
            integ_note_time(now_ns() - t, 0);
            if (map == MAP_FAILED)
                continue;
            memset(map + (off - base), val, n);
            memset(f->shadow + off, val, n);
            if (op == 0)
                msync(map, mlen, (rnd() & 1) ? MS_SYNC : MS_ASYNC);
            t = now_ns();
            munmap(map, mlen);
            integ_note_time(now_ns() - t, 1);
        } else if (op < 5) {
            memset(tmp, val, n);
            if (pwrite(f->fd, tmp, n, (off_t)off) != (ssize_t)n)
                continue;
            memcpy(f->shadow + off, tmp, n);
            if (off + n > f->len)
                f->len = off + n;
        } else if (op == 5) {
            size_t nl = (size_t)(rnd() % INTEG_MAX);
            if (ftruncate(f->fd, (off_t)nl) != 0)
                continue;
            if (nl < f->len)
                memset(f->shadow + nl, 0, f->len - nl);
            f->len = nl;
        } else if (op == 6) {
            fdatasync(f->fd);
        } else if (op < 9) {
            if (off >= f->len)
                continue;
            if (off + n > f->len)
                n = f->len - off;
            ssize_t got = pread(f->fd, tmp, n, (off_t)off);
            if (got != (ssize_t)n) {
                g_integ_mismatch++;
                fprintf(stderr, "INTEGRITY-MISMATCH %s via read short %zd of %zu at %zu (len %zu)\n",
                        f->path, got, n, off, f->len);
                continue;
            }
            integ_check(f, tmp, off, n, "read");
        } else {
            if (f->len == 0)
                continue;
            size_t mlen = (f->len + 4095) & ~4095ull;
            unsigned char *map = mmap(NULL, mlen, PROT_READ, MAP_SHARED, f->fd, 0);
            if (map == MAP_FAILED)
                continue;
            integ_check(f, map, 0, f->len, "fresh-map");
            munmap(map, mlen);
        }
        if (now_ns() >= next_hb) {
            next_hb = now_ns() + 1000000000ull;
            snprintf(line, sizeof line,
                     "ops=%llu mismatch=%llu slow_mmap=%llu slow_munmap=%llu worst_mmap_ms=%llu "
                     "worst_munmap_ms=%llu\n",
                     (unsigned long long)g_integ_ops, (unsigned long long)g_integ_mismatch,
                     (unsigned long long)g_slow_map, (unsigned long long)g_slow_unmap,
                     MS(g_worst_map), MS(g_worst_unmap));
            write_hb(hb, line);
        }
    }
    for (int i = 0; i < nfiles; i++) {
        struct integ_file *f = &files[i];
        fsync(f->fd);
        ssize_t got = pread(f->fd, tmp, f->len, 0);
        if (got != (ssize_t)f->len) {
            g_integ_mismatch++;
            fprintf(stderr, "INTEGRITY-MISMATCH %s via final-read short %zd of %zu\n", f->path,
                    got, f->len);
        } else {
            integ_check(f, tmp, 0, f->len, "final-read");
        }
        printf("INTEGRITY-FINAL %s len=%zu fnv=%016llx\n", f->path, f->len,
               (unsigned long long)fnv1a(f->shadow, f->len));
        close(f->fd);
    }
    printf("integrity: ops=%llu mismatch=%llu slow_mmap=%llu slow_munmap=%llu worst_mmap_ms=%llu "
           "worst_munmap_ms=%llu\n",
           (unsigned long long)g_integ_ops, (unsigned long long)g_integ_mismatch,
           (unsigned long long)g_slow_map, (unsigned long long)g_slow_unmap, MS(g_worst_map),
           MS(g_worst_unmap));
    return g_integ_mismatch ? 1 : 0;
}

// ── killstorm ───────────────────────────────────────────────────────

struct slot {
    pid_t pid;
    int mode, killed, reported;
    uint64_t kill_at, killed_at;
};

static void write_hb(const char *path, const char *text) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        if (write(fd, text, strlen(text)) < 0) {
        }
        close(fd);
    }
}

// `only` < 0: every slot picks any single-operation mode and lives up to a
// second. `only` >= 0: every slot runs that mode and lives 0.2-4 s.
static int killstorm(uint64_t secs, int nslots, const char *hb, int only) {
    struct slot *slots = calloc((size_t)nslots, sizeof *slots);
    uint64_t end = now_ns() + secs * 1000000000ull, next_hb = 0;
    uint64_t kills = 0, early = 0, exits = 0, unkillable = 0, max_reap_ms = 0, stuck_now = 0;
    uint64_t per_mode[NMODES] = {0};
    char line[512];
    for (;;) {
        uint64_t now = now_ns();
        int stopping = now >= end, live = 0;
        for (int i = 0; i < nslots; i++) {
            struct slot *s = &slots[i];
            if (s->pid == 0) {
                if (stopping)
                    continue;
                s->mode = only >= 0 ? only : (int)(rnd() % (NMODES - 1));
                uint64_t r = rnd() % 100;
                // Half die within 5 ms (fork, exec and first faults), most
                // of the rest within 100 ms, a few live for a second.
                uint64_t life_us = r < 50 ? rnd() % 5000 : r < 90 ? rnd() % 100000 : rnd() % 1000000;
                if (only >= 0)
                    life_us = 200000 + rnd() % 3800000;
                pid_t pid = fork();
                if (pid == 0) {
                    t_rng = 0;
                    MODES[s->mode].fn();
                    _exit(3);
                }
                if (pid < 0) {
                    usleep(1000);
                    continue;
                }
                s->pid = pid;
                s->killed = s->reported = 0;
                s->kill_at = now + life_us * 1000;
            }
            live++;
            if (!s->killed && (stopping || now >= s->kill_at)) {
                kill(s->pid, SIGKILL);
                s->killed = 1;
                s->killed_at = now;
            }
            int status;
            if (waitpid(s->pid, &status, WNOHANG) == s->pid) {
                if (s->killed) {
                    uint64_t ms = (now_ns() - s->killed_at) / 1000000;
                    if (ms > max_reap_ms)
                        max_reap_ms = ms;
                    kills++;
                    per_mode[s->mode]++;
                    if (s->reported)
                        stuck_now--;
                } else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                    exits++;
                } else {
                    early++;
                }
                s->pid = 0;
                live--;
            } else if (s->killed && !s->reported && now - s->killed_at > 20000000000ull) {
                s->reported = 1;
                unkillable++;
                stuck_now++;
                fprintf(stderr, "UNKILLABLE pid=%d mode=%s 20s after SIGKILL\n", (int)s->pid,
                        MODES[s->mode].name);
            }
        }
        if (now >= next_hb) {
            next_hb = now + 1000000000ull;
            snprintf(line, sizeof line,
                     "kills=%llu exits=%llu early=%llu maxreap_ms=%llu unkillable=%llu stuck_now=%llu\n",
                     (unsigned long long)kills, (unsigned long long)exits, (unsigned long long)early,
                     (unsigned long long)max_reap_ms, (unsigned long long)unkillable,
                     (unsigned long long)stuck_now);
            write_hb(hb, line);
        }
        if (stopping && (live == 0 || now > end + 40000000000ull))
            break;
        usleep(300);
    }
    printf("killstorm: kills=%llu exits=%llu early=%llu maxreap_ms=%llu unkillable=%llu still_stuck=%llu\n",
           (unsigned long long)kills, (unsigned long long)exits, (unsigned long long)early,
           (unsigned long long)max_reap_ms,
           (unsigned long long)unkillable, (unsigned long long)stuck_now);
    for (size_t m = 0; m < NMODES; m++)
        printf("killstorm:   %-18s %llu\n", MODES[m].name, (unsigned long long)per_mode[m]);
    return stuck_now ? 4 : 0;
}

// ── steady multi-threaded loads ─────────────────────────────────────

static int steady(uint64_t secs, int threads, op_fn fn, const char *hb) {
    pthread_t *t = calloc((size_t)threads, sizeof *t);
    char line[96];
    g_deadline_ns = now_ns() + secs * 1000000000ull;
    for (int i = 0; i < threads; i++)
        pthread_create(&t[i], NULL, thread_main, (void *)fn);
    while (now_ns() < g_deadline_ns) {
        sleep(1);
        snprintf(line, sizeof line, "%llu max_ms=%llu\n",
                 (unsigned long long)__atomic_load_n(&g_ops, __ATOMIC_RELAXED),
                 (unsigned long long)(__atomic_exchange_n(&g_lat_max_ns, 0, __ATOMIC_RELAXED) /
                                      1000000));
        write_hb(hb, line);
    }
    for (int i = 0; i < threads; i++)
        pthread_join(t[i], NULL);
    return 0;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc == 8 && strcmp(argv[1], "killstorm") == 0) {
        g_big = argv[4];
        g_tree = argv[5];
        g_scratch = argv[6];
        mkdir(g_scratch, 0755);
        collect_tree();
        return killstorm(strtoull(argv[2], NULL, 10), atoi(argv[3]), argv[7], -1);
    }
    if (argc == 7 && strcmp(argv[1], "shared") == 0) {
        g_threads = atoi(argv[4]);
        g_scratch = argv[5];
        mkdir(g_scratch, 0755);
        return killstorm(strtoull(argv[2], NULL, 10), atoi(argv[3]), argv[6], MODE_SHARED);
    }
    if (argc == 6 && strcmp(argv[1], "dirtyexit") == 0) {
        g_tree = argv[5];
        collect_tree();
        return dirtyexit(strtoull(argv[2], NULL, 10), argv[3], strcmp(argv[4], "kill") == 0);
    }
    if (argc == 7 && strcmp(argv[1], "forkparent") == 0)
        return forkparent(strtoull(argv[2], NULL, 10), strtoull(argv[3], NULL, 10),
                          atof(argv[4]), argv[5], argv[6]);
    if (argc == 4 && strcmp(argv[1], "munmapbig") == 0)
        return munmapbig(strtoull(argv[2], NULL, 10), argv[3]);
    if (argc == 4 && strcmp(argv[1], "firsttouch") == 0)
        return firsttouch(strtoull(argv[2], NULL, 10), argv[3]);
    if (argc == 5 && strcmp(argv[1], "mapchurn") == 0)
        return mapchurn(strtoull(argv[2], NULL, 10), strtoull(argv[3], NULL, 10), argv[4]);
    if (argc == 6 && strcmp(argv[1], "durable") == 0)
        return durable(argv[2], strtoull(argv[3], NULL, 10), argv[4], strtoull(argv[5], NULL, 10));
    if (argc == 5 && strcmp(argv[1], "verify") == 0)
        return verify(argv[2], strtoull(argv[3], NULL, 10), strtoull(argv[4], NULL, 10));
    if (argc == 6 && strcmp(argv[1], "integrity") == 0)
        return integrity(strtoull(argv[2], NULL, 10), argv[3], atoi(argv[4]), argv[5]);
    if (argc == 6 && strcmp(argv[1], "lookups") == 0) {
        g_tree = argv[4];
        collect_tree();
        return steady(strtoull(argv[2], NULL, 10), atoi(argv[3]), op_lookup, argv[5]);
    }
    if (argc == 6 && strcmp(argv[1], "mmapfault") == 0) {
        g_big = argv[4];
        return steady(strtoull(argv[2], NULL, 10), atoi(argv[3]), op_map_shared_read, argv[5]);
    }
    if (argc == 6 && strcmp(argv[1], "readtree") == 0) {
        g_tree = argv[4];
        collect_tree();
        return steady(strtoull(argv[2], NULL, 10), atoi(argv[3]), op_readfiles, argv[5]);
    }
    fprintf(stderr,
            "usage: soak-native killstorm <secs> <slots> <bigfile> <tree> <scratch> <hbfile>\n"
            "       soak-native shared <secs> <procs> <threads> <dir> <hbfile>\n"
            "       soak-native dirtyexit <mib> <file> <exit|kill> <tree>\n"
            "       soak-native forkparent <secs> <dirty-mib> <forks-per-sec> <file> <hbfile>\n"
            "       soak-native munmapbig <mib> <file>\n"
            "       soak-native firsttouch <mib> <file>\n"
            "       soak-native mapchurn <secs> <mib> <file>\n"
            "       soak-native durable <file> <mib> <exit|kill|msync|fsync|nosync> <seed>\n"
            "       soak-native verify <file> <mib> <seed>\n"
            "       soak-native integrity <secs> <dir> <files> <hbfile>\n"
            "       soak-native lookups <secs> <threads> <tree> <hbfile>\n"
            "       soak-native mmapfault <secs> <threads> <bigfile> <hbfile>\n"
            "       soak-native readtree <secs> <threads> <tree> <hbfile>\n");
    return 2;
}
