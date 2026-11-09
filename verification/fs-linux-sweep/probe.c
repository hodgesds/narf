/* Same static Linux-ABI workload on NARF and Linux. Diagnostic timings only. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define BLOCK 4096
#define BLOCKS 256
#define NAMES 64
static unsigned char buf[BLOCK];
static const char *step;

static void end_marker(void) { puts("FS-SWEEP-END"); }

static uint64_t now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) { perror("clock_gettime"); exit(1); }
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static unsigned char pattern(size_t offset) {
    return (unsigned char)((offset * 17 + (offset >> 8) * 31 + 91) & 255);
}

static void fill(size_t offset) {
    for (size_t i = 0; i < BLOCK; i++) buf[i] = pattern(offset + i);
}

static int verify(size_t offset) {
    for (size_t i = 0; i < BLOCK; i++)
        if (buf[i] != pattern(offset + i)) { errno = EILSEQ; return -1; }
    return 0;
}

static int transfer(int fd, size_t offset, int writing) {
    size_t done = 0;
    while (done < BLOCK) {
        ssize_t n = writing ? pwrite(fd, buf + done, BLOCK - done, offset + done)
                            : pread(fd, buf + done, BLOCK - done, offset + done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (!n) errno = EIO; return -1; }
        done += (size_t)n;
    }
    return 0;
}

static int data_case(const char *name, uint64_t *units) {
    int writing = !strcmp(name, "seq-write-sync") || !strcmp(name, "random-overwrite-sync") ||
                  !strcmp(name, "append-sync") || !strcmp(name, "fsync-each");
    int random = !strcmp(name, "random-read") || !strcmp(name, "random-overwrite-sync");
    int each = !strcmp(name, "fsync-each");
    int append = !strcmp(name, "append-sync");
    int fresh = !strcmp(name, "seq-write-sync") || each;
    const char *path = !writing ? "seed.bin" : append ? "append.bin" : !fresh ? "overwrite.bin" : name;
    step = "open";
    int fd = open(path, writing ? O_RDWR | (fresh ? O_CREAT | O_EXCL : 0) : O_RDONLY, 0644);
    if (fd < 0) return -1;
    int rc = -1;
    unsigned char written[BLOCKS + 16] = {0};
    size_t count = each ? 8 : random ? 128 : BLOCKS;
    if (!strcmp(name, "append-sync")) count = 16;
    for (size_t i = 0; i < count; i++) {
        size_t offset = (append ? BLOCKS + i : random ? (i * 97) % BLOCKS : i) * BLOCK;
        if (writing) {
            fill(offset);
            for (size_t j = 0; j < BLOCK; j++) buf[j] ^= 0xa5;
        }
        step = writing ? "pwrite" : "pread";
        if (transfer(fd, offset, writing)) goto done;
        written[offset / BLOCK] = 1;
        if (!writing && verify(offset)) { step = "verify-read"; goto done; }
        if (each) { step = "fsync"; if (fsync(fd)) goto done; }
    }
    if (writing) {
        step = "fsync";
        if (fsync(fd)) goto done;
        size_t verify_count = append ? BLOCKS + count : fresh ? count : BLOCKS;
        for (size_t i = 0; i < verify_count; i++) {
            size_t offset = i * BLOCK;
            step = "verify-write";
            if (transfer(fd, offset, 0)) goto done;
            if (written[i]) for (size_t j = 0; j < BLOCK; j++) buf[j] ^= 0xa5;
            if (verify(offset)) goto done;
        }
        struct stat st;
        step = "verify-size";
        if (fstat(fd, &st)) goto done;
        if (st.st_size != (off_t)(verify_count * BLOCK)) {
            errno = EILSEQ; goto done;
        }
    }
    *units = count * BLOCK;
    rc = 0;
done:;
    int saved = errno;
    if (close(fd) && !rc) { step = "close"; return -1; }
    errno = saved;
    return rc;
}

static int metadata_case(const char *name, uint64_t *units) {
    char path[64];
    if (!strcmp(name, "stat")) {
        for (unsigned i = 0; i < 512; i++) {
            struct stat st;
            snprintf(path, sizeof(path), "lookup/n%04u", i % NAMES);
            step = "stat";
            if (stat(path, &st)) return -1;
            if (!S_ISREG(st.st_mode) || st.st_size != 1) { errno = EILSEQ; return -1; }
        }
        *units = 512;
    } else if (!strcmp(name, "readdir")) {
        step = "opendir";
        DIR *d = opendir("lookup");
        if (!d) return -1;
        uint64_t seen = 0;
        struct dirent *entry;
        int error = 0;
        for (;;) {
            errno = 0;
            entry = readdir(d);
            if (!entry) { error = errno; break; }
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            unsigned n;
            char tail;
            if (sscanf(entry->d_name, "n%4u%c", &n, &tail) != 1 || n >= NAMES ||
                (seen & (UINT64_C(1) << n))) { error = EILSEQ; break; }
            seen |= UINT64_C(1) << n;
        }
        step = "verify-readdir";
        if (closedir(d) && !error) error = errno;
        if (error || seen != UINT64_MAX) { errno = error ? error : EILSEQ; return -1; }
        *units = NAMES;
    } else {
        for (unsigned i = 0; i < 16; i++) {
            snprintf(path, sizeof(path), "%s%04u", name, i);
            step = "create";
            int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
            if (fd < 0) return -1;
            if (close(fd)) { step = "close"; return -1; }
            if (!strcmp(name, "rename-unlink")) {
                char dest[64];
                snprintf(dest, sizeof(dest), "renamed%04u", i);
                step = "rename";
                if (rename(path, dest)) return -1;
                struct stat st;
                step = "verify-rename";
                if (stat(dest, &st)) return -1;
                if (lstat(path, &st) != -1 || errno != ENOENT) { errno = EILSEQ; return -1; }
                strcpy(path, dest);
            }
            step = "unlink";
            if (unlink(path)) return -1;
            struct stat st;
            step = "verify-unlink";
            if (lstat(path, &st) != -1 || errno != ENOENT) { errno = EILSEQ; return -1; }
        }
        step = "open-directory";
        int fd = open(".", O_RDONLY | O_DIRECTORY);
        if (fd < 0) return -1;
        step = "fsync-directory";
        int rc = fsync(fd), saved = errno;
        if (close(fd) && !rc) return -1;
        if (rc) { errno = saved; return -1; }
        *units = 16;
    }
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    atexit(end_marker);
    if (argc != 4) { fprintf(stderr, "usage: probe DEVICE FSTYPE MOUNTPOINT\n"); return 2; }
    struct utsname u;
    if (uname(&u)) { perror("uname"); return 1; }
    printf("FSIDENT sysname=%s release=%s machine=%s fs=%s\n", u.sysname, u.release, u.machine, argv[2]);
    mkdir("/tmp", 01777);
    if (mkdir(argv[3], 0755) && errno != EEXIST) { perror("mkdir mountpoint"); return 1; }
    /* Reuse NARF's boot-mounted ext volume: never construct two cache owners
       for one device. The host validates the boot mount's device identity. */
    int existing = !strcmp(argv[1], "/dev/vblk0") && !strncmp(argv[2], "ext", 3);
    if (existing && strcmp(argv[3], "/mnt")) {
        fprintf(stderr, "NARF ext workload requires the boot mount at /mnt\n"); return 2;
    }
    if (!existing && mount(argv[1], argv[3], argv[2], MS_NOATIME, NULL)) {
        printf("FSMOUNT status=error errno=%d\n", errno); return 1;
    }
    printf("FSMOUNT status=ok device=%s fs=%s existing=%d options=%s\n",
           argv[1], argv[2], existing, existing ? "boot-default" : "noatime");
    if (chdir(argv[3])) { perror("chdir"); return 1; }
    static const char *cases[] = {"seq-read-first", "seq-read-warm", "random-read", "stat", "readdir",
        "seq-write-sync", "random-overwrite-sync", "append-sync", "fsync-each", "create-unlink", "rename-unlink"};
    unsigned failed = 0;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        uint64_t units = 0;
        printf("FSBEGIN name=%s\n", cases[i]);
        uint64_t start = now();
        int rc = i < 3 || (i >= 5 && i <= 8) ? data_case(cases[i], &units)
                                             : metadata_case(cases[i], &units);
        int saved = rc ? errno : 0;
        uint64_t elapsed = now() - start;
        printf("FSCASE name=%s status=%s errno=%d step=%s units=%" PRIu64 " ns=%" PRIu64 "\n",
               cases[i], rc ? "error" : "ok", saved, step, units, elapsed);
        failed += !!rc;
    }
    int dir = open(".", O_RDONLY | O_DIRECTORY);
    int synced = dir >= 0 ? syncfs(dir) : -1;
    int saved = errno;
    /* Let deferred file-reference reclamation run before the final sync and
       guest stop. This fixed settling interval is outside every timed case. */
    struct timespec remaining = { .tv_sec = 1, .tv_nsec = 0 };
    while (nanosleep(&remaining, &remaining) && errno == EINTR) {}
    if (dir >= 0 && !synced && syncfs(dir)) { synced = -1; saved = errno; }
    if (dir >= 0 && close(dir) && !synced) { synced = -1; saved = errno; }
    chdir("/");
    int unmounted = existing ? 0 : umount(argv[3]);
    printf("FSSYNC status=%s errno=%d unmount=%d retained_boot_mount=%d\n",
           synced ? "error" : "ok", synced ? saved : 0, unmounted, existing);
    printf("FSDONE cases=%zu failed=%u\n", sizeof(cases)/sizeof(cases[0]), failed);
    return failed || synced || unmounted ? 1 : 0;
}
