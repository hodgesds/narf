/* tmpfs file + MAP_SHARED coherence test for NARF.
 *
 * The end-to-end form of `filesystem/specification/tmpfs-shared-mappings.md`.
 * A tmpfs page and its mapped page must be ONE object, so:
 *
 *   1. a write(2) is visible through an already-established mapping;
 *   2. a store through the mapping is visible to read(2), with no msync;
 *   3. two independent mappings of one file see each other's stores —
 *      the `shm_open` + `mmap` shape POSIX shared memory is built on;
 *   4. a page first touched AFTER the mapping was created still appears,
 *      i.e. the mapping TRACKS the file rather than snapshotting it.
 *
 * Before tmpfs backed its pages with physical frames, every mapping got a
 * private copy filled in at fault time and written back on msync, so (1)
 * and (2) both failed and (3) only worked by accident of both mappings
 * sharing one cached copy.
 *
 * Note this uses a tmpfs FILE, not a memfd: `memfd_create` has its own
 * frame-backed store (`MemfdStore`) and was already coherent. The path
 * this exercises is the one tmpfs files take.
 *
 * Statically linked on purpose: the dynamically-linked musl cases need
 * /lib/ld-musl-x86_64.so.1 from the Alpine rootfs, which is not present in
 * every environment this has to run in.
 *
 * Build: gcc -static -no-pie -O1 -o tmpfs_share_smoke_x86_64 \
 *            tmpfs_share_smoke_x86_64.c
 */
#define _GNU_SOURCE 1
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define PAGE 4096
#define LEN  (2 * PAGE)

static int fail(const char *why)
{
    printf("tmpfs-share: FAIL %s\n", why);
    fflush(stdout);
    return 1;
}

int main(void)
{
    int fd = open("/tmp/share-smoke", O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return fail("open /tmp/share-smoke");
    if (ftruncate(fd, LEN) != 0)
        return fail("ftruncate");

    /* Seed through write(2), THEN map: the mapping must observe bytes the
     * file already had. */
    if (pwrite(fd, "from-write", 10, 0) != 10)
        return fail("pwrite");

    char *a = mmap(NULL, LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (a == MAP_FAILED)
        return fail("mmap-a");
    if (memcmp(a, "from-write", 10) != 0)
        return fail("write(2) not visible through the mapping");

    /* (2) a store through the mapping reaches read(2) with no msync. */
    memcpy(a, "from-mmap", 9);
    char buf[16] = {0};
    if (pread(fd, buf, 9, 0) != 9)
        return fail("pread");
    if (memcmp(buf, "from-mmap", 9) != 0)
        return fail("mapped store not visible to read(2)");

    /* (1) again, in the other direction and after the fault: a write(2)
     * must land in the page the mapping already holds. */
    if (pwrite(fd, "second-wr", 9, 0) != 9)
        return fail("pwrite 2");
    if (memcmp(a, "second-wr", 9) != 0)
        return fail("write(2) after fault not visible through the mapping");

    /* (3) two independent mappings of the same memfd. */
    char *b = mmap(NULL, LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (b == MAP_FAILED)
        return fail("mmap-b");
    if (b == a)
        return fail("the two mappings landed at one address");
    memcpy(b + 32, "cross-map", 9);
    if (memcmp(a + 32, "cross-map", 9) != 0)
        return fail("two mappings of one memfd do not share pages");

    /* (4) the SECOND page is untouched so far. Reaching it through the
     * mapping must produce the file's page, not a detached copy. */
    memcpy(a + PAGE, "page-two", 8);
    char tail[16] = {0};
    if (pread(fd, tail, 8, PAGE) != 8)
        return fail("pread page 2");
    if (memcmp(tail, "page-two", 8) != 0)
        return fail("a page first touched through the mapping is not the file's");

    munmap(a, LEN);
    munmap(b, LEN);
    close(fd);
    unlink("/tmp/share-smoke");
    printf("tmpfs-share-ok\n");
    fflush(stdout);
    return 0;
}
