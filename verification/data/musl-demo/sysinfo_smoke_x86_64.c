// sysinfo(2) smoke. Call sysinfo() and verify it succeeds and reports
// a non-zero total RAM. Success token "sysinfo-ok".
//
// Build: see REGEN_sysinfo_smoke.sh (musl-gcc, static-PIE).
#include <sys/sysinfo.h>
#include <unistd.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    struct sysinfo si;
    memset(&si, 0, sizeof si);
    if (sysinfo(&si) != 0) {
        w("sysinfo-fail: call\n");
        return 1;
    }
    if (si.totalram > 0) {
        w("sysinfo-ok\n");
    } else {
        w("sysinfo-fail: ram\n");
    }
    return 0;
}
