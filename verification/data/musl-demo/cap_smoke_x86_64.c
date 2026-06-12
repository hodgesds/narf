// capget(2) / capset(2) smoke. musl ships no wrappers for these, so we
// issue them raw via syscall(2). Set a 64-bit (v3) capability triple,
// read it back, and confirm an unsupported version is rejected with the
// header rewritten to the preferred version. Success token "cap-ok".
//
// Build: see REGEN_cap_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdint.h>

static void w(const char *m) { write(1, m, strlen(m)); }

struct cap_header { uint32_t version; int pid; };
struct cap_data { uint32_t effective, permitted, inheritable; };

#define CAP_V3 0x20080522u

int main(void) {
    struct cap_header hdr = { CAP_V3, 0 };
    struct cap_data set[2];
    memset(set, 0, sizeof set);
    // 64-bit caps split lo (data[0]) / hi (data[1]).
    set[0].effective = 0x12345678u;  set[1].effective = 0x9u;
    set[0].permitted = 0xdeadbeefu;  set[1].permitted = 0x1u;
    if (syscall(SYS_capset, &hdr, set) != 0) { w("cap-fail: capset\n"); return 1; }

    struct cap_header hdr2 = { CAP_V3, 0 };
    struct cap_data got[2];
    memset(got, 0, sizeof got);
    if (syscall(SYS_capget, &hdr2, got) != 0) { w("cap-fail: capget\n"); return 1; }
    if (got[0].effective != 0x12345678u || got[1].effective != 0x9u) {
        w("cap-fail: eff-mismatch\n"); return 1;
    }
    if (got[0].permitted != 0xdeadbeefu || got[1].permitted != 0x1u) {
        w("cap-fail: perm-mismatch\n"); return 1;
    }

    // An unsupported version must fail and rewrite the header to V3.
    struct cap_header bad = { 0xdeadbeefu, 0 };
    if (syscall(SYS_capget, &bad, (void *)0) == 0) {
        w("cap-fail: badver-accepted\n"); return 1;
    }
    if (bad.version != CAP_V3) { w("cap-fail: badver-norewrite\n"); return 1; }

    w("cap-ok\n");
    return 0;
}
