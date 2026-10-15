// W|X mappings for JIT engines — what V8 does with its code range.
//
// V8 reserves its code range PROT_NONE and then makes it RWX in one step:
// with memory protection keys it calls pkey_mprotect(base, size,
// PROT_READ|PROT_WRITE|PROT_EXEC, pkey) and CHECKs that the only acceptable
// failure is ENOMEM (CodeRange::InitReservation). Every Chromium renderer
// died on that CHECK when NARF refused a W|X end state with EACCES.
//
// Linux grants W|X to mprotect/pkey_mprotect unless the process opted into
// PR_SET_MDWE (memory-deny-write-execute), which then refuses with EACCES.
//
// Checks, each against Linux:
//   1. PROT_NONE -> RWX via mprotect, then generated code runs.
//   2. RW -> RWX and RX -> RWX via mprotect.
//   3. PROT_NONE -> RWX via pkey_mprotect with an allocated key (V8's call);
//      skipped when the CPU/kernel has no pkeys (pkey_alloc fails).
//   4. MDWE (in a child): RW -> RWX is EACCES.
// Success token "jitrwx-ok".
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PR_SET_MDWE
#define PR_SET_MDWE 65
#endif
#ifndef PR_MDWE_REFUSE_EXEC_GAIN
#define PR_MDWE_REFUSE_EXEC_GAIN 1
#endif

static int fails;

static void check(int ok, const char *what) {
    if (!ok) {
        printf("jitrwx-fail: %s (errno=%d)\n", what, errno);
        fails++;
    }
}

// mov eax, 42 ; ret
static const unsigned char code42[] = {0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3};

static int run_code(void *page) {
    memcpy(page, code42, sizeof(code42));
    int (*fn)(void) = (int (*)(void))page;
    return fn();
}

int main(void) {
    const size_t len = 4 * 4096;

    // 1. PROT_NONE reservation made RWX, then executed.
    unsigned char *p = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(p != MAP_FAILED, "mmap PROT_NONE");
    errno = 0;
    check(mprotect(p, len, PROT_READ | PROT_WRITE | PROT_EXEC) == 0, "mprotect NONE->RWX");
    check(run_code(p) == 42, "generated code in an RWX page returned 42");

    // 2. RW -> RWX, and RX -> RWX (adding W to an executable mapping).
    unsigned char *q = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(q != MAP_FAILED, "mmap RW");
    check(mprotect(q, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0, "mprotect RW->RWX");
    check(run_code(q) == 42, "code in an RW->RWX page");
    check(mprotect(q + 4096, 4096, PROT_READ | PROT_EXEC) == 0, "mprotect RW->RX");
    check(mprotect(q + 4096, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0, "mprotect RX->RWX");
    check(run_code(q + 4096) == 42, "code in an RX->RWX page");

    // 3. pkey_mprotect RWX, V8's exact call.
    int key = (int)syscall(SYS_pkey_alloc, 0, 0);
    if (key >= 0) {
        unsigned char *r = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        check(r != MAP_FAILED, "mmap PROT_NONE for pkey");
        check(syscall(SYS_pkey_mprotect, r, len, PROT_READ | PROT_WRITE | PROT_EXEC, key) == 0,
              "pkey_mprotect NONE->RWX with an allocated key");
        syscall(SYS_pkey_free, key);
    } else {
        printf("jitrwx: pkey_alloc unavailable (errno=%d), pkey case skipped\n", errno);
    }

    // 4. MDWE refuses the W|X end state. In a child: MDWE cannot be cleared.
    pid_t c = fork();
    if (c == 0) {
        if (prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) != 0) {
            printf("jitrwx: PR_SET_MDWE unavailable (errno=%d)\n", errno);
            _exit(0);
        }
        unsigned char *s = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        errno = 0;
        int rc = mprotect(s, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
        if (rc != -1 || errno != EACCES) {
            printf("jitrwx-fail: MDWE mprotect RW->RWX rc=%d errno=%d, want -1/EACCES\n", rc, errno);
            _exit(1);
        }
        _exit(0);
    }
    int st = 0;
    check(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0, "MDWE child");

    if (fails == 0)
        printf("jitrwx-ok\n");
    return fails != 0;
}
