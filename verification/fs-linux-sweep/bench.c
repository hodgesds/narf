/* Fixed-work, synchronous filesystem benchmark. One sample per fresh guest.
 * Verification and setup are outside the reported TSC intervals. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <unistd.h>

#define FILE_BYTES (8u * 1024 * 1024)
#define CHUNK 65536u
#define PAGE 4096u
#define RANDOM_OPS 4096u
#define NAMES 1024u
#define CREATED 128u
static unsigned char data[FILE_BYTES];
static unsigned char scratch[RANDOM_OPS * PAGE];
static char names[NAMES][32];

struct stamp { uint64_t cycles; unsigned cpu; };
static struct stamp stamp(void) {
    unsigned lo, hi, cpu;
    __asm__ __volatile__("lfence; rdtscp; lfence" : "=a"(lo), "=d"(hi), "=c"(cpu) :: "memory");
    return (struct stamp){ ((uint64_t)hi << 32) | lo, cpu };
}

static void require(int ok, const char *what) {
    if (!ok) { printf("FSBENCH_FAIL step=%s errno=%d\n", what, errno); exit(1); }
}

static uint64_t elapsed(struct stamp a, struct stamp b) {
    require(a.cpu == b.cpu && (a.cpu & 0xfff) == 0 && b.cycles > a.cycles, "stable-cpu-and-tsc");
    return b.cycles - a.cycles;
}

static void metric(const char *name, uint64_t cycles, uint64_t units, const char *unit) {
    require(cycles > 0, "positive-duration");
    printf("FSBENCH name=%s cycles=%" PRIu64 " work=%" PRIu64 " unit=%s\n", name, cycles, units, unit);
}

static unsigned char byte_at(size_t offset) {
    return (unsigned char)((offset * 17 + (offset >> 8) * 31 + 91) & 255);
}

static void check(const unsigned char *bytes, size_t offset, size_t size, unsigned salt) {
    for (size_t i = 0; i < size; i++) {
        if (bytes[i] != (unsigned char)(byte_at(offset + i) ^ salt)) {
            errno = EILSEQ; require(0, "file-bytes");
        }
    }
}

static void io(int fd, unsigned char *bytes, size_t size, size_t offset, int writing) {
    size_t done = 0;
    while (done < size) {
        ssize_t n = writing ? pwrite(fd, bytes + done, size - done, (off_t)(offset + done))
                            : pread(fd, bytes + done, size - done, (off_t)(offset + done));
        if (n < 0 && errno == EINTR) continue;
        require(n > 0, writing ? "pwrite" : "pread");
        done += (size_t)n;
    }
}

static int file(const char *path, int flags) {
    int fd = open(path, flags, 0644);
    require(fd >= 0, "open"); return fd;
}

static void full_read(int fd, unsigned char *bytes, size_t size) {
    for (size_t offset = 0; offset < size; offset += CHUNK)
        io(fd, bytes + offset, CHUNK < size - offset ? CHUNK : size - offset, offset, 0);
}

static void reads(void) {
    int fd = file("seed.bin", O_RDONLY);
    struct stamp a = stamp();
    full_read(fd, data, FILE_BYTES);
    uint64_t cycles = elapsed(a, stamp());
    check(data, 0, FILE_BYTES, 0);
    metric("first-read-64k", cycles, FILE_BYTES, "bytes");
    for (unsigned warmup = 0; warmup < 2; warmup++) full_read(fd, data, FILE_BYTES);
    cycles = 0;
    for (unsigned pass = 0; pass < 16; pass++) {
        a = stamp(); full_read(fd, data, FILE_BYTES); cycles += elapsed(a, stamp());
        check(data, 0, FILE_BYTES, 0);
    }
    metric("cached-read-64k", cycles, 16ull * FILE_BYTES, "bytes");
    /* The previous reads deliberately warm this same file. Keep every random
       result until after timing so correctness work cannot dominate the sample. */
    a = stamp();
    for (unsigned i = 0; i < RANDOM_OPS; i++) {
        size_t offset = ((size_t)i * 97 % (FILE_BYTES / PAGE)) * PAGE;
        io(fd, scratch + (size_t)i * PAGE, PAGE, offset, 0);
    }
    cycles = elapsed(a, stamp());
    for (unsigned i = 0; i < RANDOM_OPS; i++)
        check(scratch + (size_t)i * PAGE, ((size_t)i * 97 % (FILE_BYTES / PAGE)) * PAGE, PAGE, 0);
    metric("cached-random-read-4k", cycles, (uint64_t)RANDOM_OPS * PAGE, "bytes");
    require(close(fd) == 0, "close-read");
}

static void writes(void) {
    for (size_t i = 0; i < FILE_BYTES; i++) data[i] = byte_at(i) ^ 0xa5;
    int fd = file("out-sequential", O_CREAT | O_EXCL | O_RDWR);
    struct stamp a = stamp();
    for (size_t offset = 0; offset < FILE_BYTES; offset += CHUNK)
        io(fd, data + offset, CHUNK, offset, 1);
    require(fsync(fd) == 0, "fsync-sequential");
    uint64_t cycles = elapsed(a, stamp());
    full_read(fd, data, FILE_BYTES); check(data, 0, FILE_BYTES, 0xa5);
    metric("sequential-write-64k-fsync", cycles, FILE_BYTES, "bytes");
    require(close(fd) == 0, "close-sequential");

    fd = file("overwrite.bin", O_RDWR);
    a = stamp();
    for (unsigned i = 0; i < RANDOM_OPS; i++) {
        size_t offset = ((size_t)i * 97 % (FILE_BYTES / PAGE)) * PAGE;
        io(fd, data + offset, PAGE, offset, 1);
    }
    require(fsync(fd) == 0, "fsync-overwrite");
    cycles = elapsed(a, stamp());
    full_read(fd, data, FILE_BYTES); check(data, 0, FILE_BYTES, 0xa5);
    metric("random-overwrite-4k-fsync", cycles, (uint64_t)RANDOM_OPS * PAGE, "bytes");
    require(close(fd) == 0, "close-overwrite");

    fd = file("append.bin", O_RDWR);
    for (size_t i = 0; i < CHUNK; i++) data[i] = byte_at(FILE_BYTES + i) ^ 0x5a;
    a = stamp();
    io(fd, data, CHUNK, FILE_BYTES, 1);
    require(fsync(fd) == 0, "fsync-append");
    cycles = elapsed(a, stamp());
    full_read(fd, scratch, FILE_BYTES + CHUNK);
    check(scratch, 0, FILE_BYTES, 0); check(scratch + FILE_BYTES, FILE_BYTES, CHUNK, 0x5a);
    struct stat st;
    require(fstat(fd, &st) == 0 && st.st_size == FILE_BYTES + CHUNK, "append-size");
    metric("append-64k-fsync", cycles, CHUNK, "bytes");
    require(close(fd) == 0, "close-append");

    fd = file("out-fsync-each", O_CREAT | O_EXCL | O_RDWR);
    for (size_t i = 0; i < 64 * PAGE; i++) data[i] = byte_at(i) ^ 0x3c;
    a = stamp();
    for (unsigned i = 0; i < 64; i++) {
        io(fd, data + i * PAGE, PAGE, i * PAGE, 1);
        require(fsync(fd) == 0, "fsync-each");
    }
    cycles = elapsed(a, stamp());
    full_read(fd, scratch, 64 * PAGE); check(scratch, 0, 64 * PAGE, 0x3c);
    metric("write-4k-fsync-each", cycles, 64, "operations");
    require(close(fd) == 0, "close-fsync-each");
}

static void metadata(void) {
    static struct stat stats[16384];
    memset(stats, 0, sizeof(stats));
    for (unsigned i = 0; i < NAMES; i++) snprintf(names[i], sizeof(names[i]), "lookup/n%04u", i);
    for (unsigned warmup = 0; warmup < 2; warmup++)
        for (unsigned i = 0; i < NAMES; i++) require(stat(names[i], &stats[i]) == 0, "warmup-stat");
    struct stamp a = stamp();
    for (unsigned i = 0; i < 16384; i++) require(stat(names[i % NAMES], &stats[i]) == 0, "stat");
    uint64_t cycles = elapsed(a, stamp());
    for (unsigned i = 0; i < 16384; i++)
        require(S_ISREG(stats[i].st_mode) && stats[i].st_size == 1, "verify-stat");
    metric("cached-stat", cycles, 16384, "operations");

    unsigned seen[32] = {0};
    a = stamp();
    for (unsigned pass = 0; pass < 32; pass++) {
        DIR *dir = opendir("lookup"); require(dir != NULL, "opendir");
        for (;;) {
            errno = 0; struct dirent *entry = readdir(dir);
            if (!entry) { require(errno == 0, "readdir"); break; }
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            seen[pass]++;
        }
        require(closedir(dir) == 0, "closedir");
    }
    cycles = elapsed(a, stamp());
    for (unsigned i = 0; i < 32; i++) require(seen[i] == NAMES, "verify-directory-count");
    metric("readdir", cycles, 32 * NAMES, "entries");

    for (unsigned i = 0; i < CREATED; i++) snprintf(names[i], sizeof(names[i]), "created%04u", i);
    int dir = file(".", O_RDONLY | O_DIRECTORY);
    a = stamp();
    for (unsigned i = 0; i < CREATED; i++) {
        int fd = file(names[i], O_CREAT | O_EXCL | O_WRONLY);
        require(close(fd) == 0, "close-created");
    }
    require(fsync(dir) == 0, "fsync-created-directory");
    cycles = elapsed(a, stamp()); metric("create-directory-fsync", cycles, CREATED, "operations");
    a = stamp();
    for (unsigned i = 0; i < CREATED; i++) {
        char renamed[32]; snprintf(renamed, sizeof(renamed), "renamed%04u", i);
        require(rename(names[i], renamed) == 0, "rename");
    }
    require(fsync(dir) == 0, "fsync-renamed-directory");
    cycles = elapsed(a, stamp());
    for (unsigned i = 0; i < CREATED; i++) {
        char renamed[32]; snprintf(renamed, sizeof(renamed), "renamed%04u", i);
        require(stat(renamed, &stats[i]) == 0 && stats[i].st_size == 0, "renamed-file");
        require(lstat(names[i], &stats[i]) < 0 && errno == ENOENT, "old-name-absent");
    }
    metric("rename-directory-fsync", cycles, CREATED, "operations");
    require(close(dir) == 0, "close-directory");
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    require(argc == 4, "usage-device-fstype-mountpoint");
    int native = !strcmp(argv[1], "native");
    long flags = personality(0xffffffffUL);
    require(flags >= 0, "query-personality");
    if (!native && !(flags & ADDR_NO_RANDOMIZE)) {
        require(!getenv("FSBENCH_REEXEC"), "aslr-persisted-over-exec");
        require(personality((unsigned long)flags | ADDR_NO_RANDOMIZE) >= 0, "disable-aslr");
        require(setenv("FSBENCH_REEXEC", "1", 1) == 0, "reexec-env");
        execv(argv[0], argv); require(0, "reexec");
    }
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(0, &set);
    require(sched_setaffinity(0, sizeof(set), &set) == 0, "pin-guest-cpu");
    printf("FSBENCH_ENV native=%d no_randomize=%d file_bytes=%u random_ops=%u names=%u\n",
           native, !!(flags & ADDR_NO_RANDOMIZE), FILE_BYTES, RANDOM_OPS, NAMES);
    mkdir("/tmp", 01777);
    int existing = !strcmp(argv[1], "/dev/vblk0") && !strncmp(argv[2], "ext", 3);
    if (!native) {
        require(mkdir(argv[3], 0755) == 0 || errno == EEXIST, "mkdir-mountpoint");
        require(mount(existing ? NULL : argv[1], argv[3], existing ? NULL : argv[2],
                      MS_NOATIME | (existing ? MS_REMOUNT : 0), NULL) == 0, "mount-noatime");
    }
    require(chdir(argv[3]) == 0, "chdir");
    memset(data, 0, sizeof(data)); memset(scratch, 0, sizeof(scratch));
    for (unsigned i = 0; i < 2; i++) {
        char name[32]; snprintf(name, sizeof(name), "warmup%u", i);
        int fd = file(name, O_CREAT | O_EXCL | O_RDWR);
        io(fd, data, PAGE, 0, 1); require(fsync(fd) == 0, "warmup-fsync");
        require(close(fd) == 0, "warmup-close");
    }
    reads(); writes(); metadata();
    int dir = file(".", O_RDONLY | O_DIRECTORY);
    require(syncfs(dir) == 0, "syncfs"); require(close(dir) == 0, "close-syncfs");
    require(chdir("/") == 0, "chdir-root");
    if (!native && !existing) require(umount(argv[3]) == 0, "unmount");
    puts("FSBENCH_DONE cases=11");
    return 0;
}
