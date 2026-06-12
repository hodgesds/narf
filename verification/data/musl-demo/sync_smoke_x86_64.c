// sync(2) + syncfs(2) + personality(2) smoke. sync() returns, syncfs
// on stdout succeeds, and personality(0xffffffff) queries the current
// execution domain (PER_LINUX). Uses raw syscall() for syncfs and
// personality. Success token "sync-ok".
//
// Build: see REGEN_sync_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    sync();
    if (syscall(SYS_syncfs, 1) != 0) {
        w("sync-fail: syncfs\n");
        return 1;
    }
    long persona = syscall(SYS_personality, 0xffffffffUL);
    if (persona < 0) {
        w("sync-fail: personality\n");
        return 1;
    }
    w("sync-ok\n");
    return 0;
}
