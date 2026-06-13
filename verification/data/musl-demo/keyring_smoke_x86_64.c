// Keyrings smoke: add_key / request_key / keyctl against NARF's in-kernel
// key store. No musl wrappers exist for these (keyutils is a separate
// library), so they're issued raw. Exercises the full lifecycle: add, read
// back, look up by type+description (request_key + KEYCTL_SEARCH), update,
// describe, revoke (then a read must fail EKEYREVOKED), and a miss must
// return ENOKEY. Success token "keyring-ok".
//
// Build: see REGEN_keyring_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/syscall.h>

#ifndef SYS_add_key
#define SYS_add_key 248
#endif
#ifndef SYS_request_key
#define SYS_request_key 249
#endif
#ifndef SYS_keyctl
#define SYS_keyctl 250
#endif

// keyctl operations + the session-keyring special id.
#define KEYCTL_UPDATE 2
#define KEYCTL_REVOKE 3
#define KEYCTL_DESCRIBE 6
#define KEYCTL_SEARCH 10
#define KEYCTL_READ 11
#define KEY_SPEC_SESSION_KEYRING (-3)

static void w(const char *m) { write(1, m, strlen(m)); }

static long add_key(const char *type, const char *desc, const void *p, size_t n, int ring) {
    return syscall(SYS_add_key, type, desc, p, n, (long)ring);
}
static long request_key(const char *type, const char *desc, int ring) {
    return syscall(SYS_request_key, type, desc, (const char *)0, (long)ring);
}
static long keyctl(int op, long a2, long a3, long a4, long a5) {
    return syscall(SYS_keyctl, (long)op, a2, a3, a4, a5);
}

int main(void) {
    char buf[64];

    // ── add a key, read its payload back verbatim ──
    long s = add_key("user", "narf:k1", "payload-v1", 10, KEY_SPEC_SESSION_KEYRING);
    if (s <= 0) { w("keyring-fail: add_key\n"); return 1; }
    long n = keyctl(KEYCTL_READ, s, (long)buf, (long)sizeof buf, 0);
    if (n != 10 || memcmp(buf, "payload-v1", 10) != 0) { w("keyring-fail: read\n"); return 1; }

    // ── look the key up by (type, description) two ways ──
    if (request_key("user", "narf:k1", KEY_SPEC_SESSION_KEYRING) != s) {
        w("keyring-fail: request_key\n"); return 1;
    }
    if (keyctl(KEYCTL_SEARCH, KEY_SPEC_SESSION_KEYRING, (long)"user", (long)"narf:k1", 0) != s) {
        w("keyring-fail: search\n"); return 1;
    }

    // ── update the payload in place, confirm the new value ──
    if (keyctl(KEYCTL_UPDATE, s, (long)"v2", 2, 0) != 0) { w("keyring-fail: update\n"); return 1; }
    n = keyctl(KEYCTL_READ, s, (long)buf, (long)sizeof buf, 0);
    if (n != 2 || memcmp(buf, "v2", 2) != 0) { w("keyring-fail: read-after-update\n"); return 1; }

    // ── describe renders "type;uid;gid;perm;description" ──
    n = keyctl(KEYCTL_DESCRIBE, s, (long)buf, (long)sizeof buf, 0);
    if (n <= 0 || strncmp(buf, "user;", 5) != 0) { w("keyring-fail: describe\n"); return 1; }

    // ── revoke tombstones the key; a subsequent read is EKEYREVOKED ──
    if (keyctl(KEYCTL_REVOKE, s, 0, 0, 0) != 0) { w("keyring-fail: revoke\n"); return 1; }
    if (keyctl(KEYCTL_READ, s, (long)buf, (long)sizeof buf, 0) != -1 || errno != EKEYREVOKED) {
        w("keyring-fail: read-after-revoke\n"); return 1;
    }

    // ── a lookup miss is ENOKEY (no upcall) ──
    if (request_key("user", "narf:no-such-key", KEY_SPEC_SESSION_KEYRING) != -1 || errno != ENOKEY) {
        w("keyring-fail: enokey\n"); return 1;
    }

    w("keyring-ok\n");
    return 0;
}
