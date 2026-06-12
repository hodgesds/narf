// sethostname(2) + setdomainname(2) smoke. Set the host and domain
// names, then read them back via gethostname (musl routes this through
// uname) and uname's domainname field. Success token "host-ok".
//
// Build: see REGEN_host_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    if (sethostname("narfhost", 8) != 0) {
        w("host-fail: sethostname\n");
        return 1;
    }
    char hn[64] = {0};
    if (gethostname(hn, sizeof hn) != 0) {
        w("host-fail: gethostname\n");
        return 1;
    }
    if (strcmp(hn, "narfhost") != 0) {
        w("host-fail: hostmismatch\n");
        return 1;
    }

    if (syscall(SYS_setdomainname, "narfdom", 7) != 0) {
        w("host-fail: setdomainname\n");
        return 1;
    }
    struct utsname u;
    memset(&u, 0, sizeof u);
    if (uname(&u) != 0) {
        w("host-fail: uname\n");
        return 1;
    }
    if (strcmp(u.nodename, "narfhost") != 0) {
        w("host-fail: nodename\n");
        return 1;
    }
    if (strcmp(u.domainname, "narfdom") != 0) {
        w("host-fail: domainname\n");
        return 1;
    }

    w("host-ok\n");
    return 0;
}
