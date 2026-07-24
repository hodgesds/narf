// Unlinked-but-still-open file smoke. POSIX: unlink(2) removes the NAME;
// the inode and its data survive until the last open fd is closed, and
// reads/writes through that fd keep working.
//
// This is not a corner case — bash implements EVERY here-document by
// writing the body to a temp file, unlinking it immediately, and reading
// the body back through the still-open fd. If the data dies with the
// name, every `cat > file <<'EOF' ... EOF` in every shell script silently
// produces an EMPTY file. On NARF that quietly blanked the KDE
// `startkderc` a launcher wrote, so the setting it contained never took
// effect.
//
// Success token "unlinkopen-ok".
//
// Build: see REGEN_unlinkopen_smoke.sh (musl-gcc, PIE).
#define _GNU_SOURCE 1
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

static void w(const char *m) { write(1, m, strlen(m)); }

#define PATH "/tmp/unlinkopen.probe"
static const char PAYLOAD[] = "here-document-body\n";

int main(void) {
    const size_t len = sizeof(PAYLOAD) - 1;

    int fd = open(PATH, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        w("unlinkopen-fail: create\n");
        return 1;
    }
    if (write(fd, PAYLOAD, len) != (ssize_t)len) {
        w("unlinkopen-fail: write\n");
        return 1;
    }

    // Drop the name while the fd stays open — bash's here-doc dance.
    if (unlink(PATH) != 0) {
        w("unlinkopen-fail: unlink\n");
        return 1;
    }
    // The name is gone...
    if (access(PATH, F_OK) == 0) {
        w("unlinkopen-fail: name still resolves after unlink\n");
        return 1;
    }
    // ...but the fd still refers to the inode, with its size intact.
    struct stat st;
    if (fstat(fd, &st) != 0 || (size_t)st.st_size != len) {
        w("unlinkopen-fail: fstat lost the size after unlink\n");
        return 1;
    }
    // And the bytes are still readable from the start.
    if (lseek(fd, 0, SEEK_SET) != 0) {
        w("unlinkopen-fail: lseek\n");
        return 1;
    }
    char buf[64];
    memset(buf, 0, sizeof(buf));
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n != (ssize_t)len || memcmp(buf, PAYLOAD, len) != 0) {
        w("unlinkopen-fail: data died with the name\n");
        return 1;
    }
    // Writes through the unlinked fd keep working too.
    if (lseek(fd, 0, SEEK_END) != (off_t)len || write(fd, "x", 1) != 1) {
        w("unlinkopen-fail: append to unlinked fd\n");
        return 1;
    }
    if (fstat(fd, &st) != 0 || (size_t)st.st_size != len + 1) {
        w("unlinkopen-fail: append did not grow the unlinked inode\n");
        return 1;
    }
    close(fd);

    w("unlinkopen-ok\n");
    return 0;
}
