// Parent-writer / child-reader pipe regressions — the X server's Popen("w")
// shape, which is how Xwayland hands a generated XKB keymap to xkbcomp.
//
// Every other pipe smoke in this tree runs the common direction: the CHILD
// owns the last write end and the parent reads. Popen("w") is the mirror
// image, and its fd bookkeeping is the part that was never covered:
//
//     pipe(p); fork();
//     child:  dup2(p[0], 0); close(p[0]); close(p[1]);  <-- closes the
//             read-loop on fd 0                              INHERITED writer
//     parent: fdopen(p[1], "w"); close(p[0]); fwrite(...); fclose();
//
// The child closing its inherited copy of p[1] must NOT make the read end
// report end-of-file: the parent still holds the last writer. If writer
// accounting is per-close rather than per-open-file-description, the child's
// close drops the count to zero, the reader sees an instant EOF, and the
// producer's bytes are silently discarded. Live symptom on NARF: Xwayland's
// xkbcomp child read a ZERO-byte keymap from stdin and reported
// "syntax error: line 1 of stdin", so keymap compilation failed, the virtual
// core keyboard never activated, and ksmserver's forced-XCB startup aborted.
//
// Cases:
//   1. Popen("w") shape with a delayed producer. The child must block in
//      read(2) — not collect EOF — until the parent's bytes arrive, and must
//      then see EOF only after the parent closes.
//   2. The same handoff larger than one pipe buffer, so the producer blocks
//      mid-write and only completes as the consumer drains. This is the real
//      keymap size class.
//   3. The producer writes through a buffered stdio stream and flushes at
//      fclose(3), exactly as XkbDDXCompileKeymapByNames does.
//
// Success token: "popenw-ok".
// Build: see REGEN_popenw_smoke.sh (musl-gcc, PIE).
#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#define SMALL_LEN 512
#define LARGE_LEN (96 * 1024)

static void w(const char *m) { write(STDOUT_FILENO, m, strlen(m)); }

static void producer_delay(void) {
    // Long enough that the consumer is parked inside read(2) before the first
    // byte exists, on any vCPU count.
    const struct timespec d = { .tv_sec = 0, .tv_nsec = 150 * 1000 * 1000 };
    nanosleep(&d, NULL);
}

static char payload_byte(size_t i) { return (char) ('A' + (int) (i % 47)); }

// Consumer side of the Popen("w") shape: stdin is the pipe, and the inherited
// write end is closed here. Returns 0 on success.
static int consume_stdin(size_t expect) {
    size_t got = 0;
    char buf[4096];
    for (;;) {
        ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n < 0) {
            return 41;
        }
        if (n == 0) {
            break; // EOF: the parent closed the last writer
        }
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] != payload_byte(got + (size_t) i)) {
                return 42;
            }
        }
        got += (size_t) n;
    }
    if (got != expect) {
        // The diagnostic case: got == 0 means the child's own close(p[1])
        // was mistaken for the last writer going away.
        return got == 0 ? 43 : 44;
    }
    return 0;
}

static pid_t spawn_consumer(int p[2], size_t expect) {
    pid_t c = fork();
    if (c != 0) {
        return c;
    }
    // Exactly xserver's Popen(): move the read end onto stdin, then drop both
    // inherited descriptors.
    if (p[0] != STDIN_FILENO) {
        if (dup2(p[0], STDIN_FILENO) < 0) {
            _exit(40);
        }
        close(p[0]);
    }
    close(p[1]);
    _exit(consume_stdin(expect));
}

static int reap(pid_t c, const char *label) {
    int st = 0;
    if (waitpid(c, &st, 0) != c) {
        w("popenw-fail: waitpid ");
        w(label);
        w("\n");
        return 0;
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        if (WIFEXITED(st) && WEXITSTATUS(st) == 43) {
            w("popenw-fail: consumer saw EOF with zero bytes (");
            w(label);
            w(") — the child's inherited writer close ended the pipe\n");
        } else {
            w("popenw-fail: consumer status ");
            w(label);
            w("\n");
        }
        return 0;
    }
    return 1;
}

// Raw write(2) producer.
static int raw_round(size_t len, int delay, const char *label) {
    int p[2];
    if (pipe(p) != 0) {
        w("popenw-fail: pipe\n");
        return 0;
    }
    pid_t c = spawn_consumer(p, len);
    if (c < 0) {
        w("popenw-fail: fork\n");
        return 0;
    }
    close(p[0]);
    if (delay) {
        producer_delay();
    }
    size_t sent = 0;
    while (sent < len) {
        char chunk[8192];
        size_t n = len - sent;
        if (n > sizeof(chunk)) {
            n = sizeof(chunk);
        }
        for (size_t i = 0; i < n; i++) {
            chunk[i] = payload_byte(sent + i);
        }
        ssize_t r = write(p[1], chunk, n);
        if (r <= 0) {
            w("popenw-fail: producer write\n");
            close(p[1]);
            waitpid(c, NULL, 0);
            return 0;
        }
        sent += (size_t) r;
    }
    close(p[1]);
    return reap(c, label);
}

// Buffered stdio producer — the exact XkbDDXCompileKeymapByNames path.
static int stdio_round(size_t len) {
    int p[2];
    if (pipe(p) != 0) {
        w("popenw-fail: stdio pipe\n");
        return 0;
    }
    pid_t c = spawn_consumer(p, len);
    if (c < 0) {
        w("popenw-fail: stdio fork\n");
        return 0;
    }
    close(p[0]);
    FILE *out = fdopen(p[1], "w");
    if (!out) {
        w("popenw-fail: fdopen\n");
        close(p[1]);
        waitpid(c, NULL, 0);
        return 0;
    }
    producer_delay();
    for (size_t i = 0; i < len; i++) {
        if (fputc(payload_byte(i), out) == EOF) {
            w("popenw-fail: fputc\n");
            fclose(out);
            waitpid(c, NULL, 0);
            return 0;
        }
    }
    // fclose flushes; a silently dropped flush is the other way a producer
    // hands its consumer nothing.
    if (fclose(out) != 0) {
        w("popenw-fail: fclose flush\n");
        waitpid(c, NULL, 0);
        return 0;
    }
    return reap(c, "stdio");
}

// ── The child EXECs before it reads ───────────────────────────────────
//
// Everything above forks a consumer that reads the pipe directly. The real
// X server path does NOT: XkbDDXCompileKeymapByNames runs
// `Popen(cmd, "w")`, whose child execs `/bin/sh -c "xkbcomp ..."`, so the
// keymap has to survive the child's execve(2) — twice, since the shell then
// execs xkbcomp. Nothing here covered that, and it is where NARF loses the
// data: xkbcomp read a ZERO-byte keymap ("XKBCOMP-CAPTURE ... bytes=0"),
// which is what kills Xwayland's virtual core keyboard.
//
// The dup2'd read end must survive exec: fd 0 is not close-on-exec, and the
// bytes the parent wrote before (or after) the exec must still be readable
// by the newly-exec'd image.
static char self_path[512];

// `--drain N`: read stdin to EOF, verify the payload pattern and that
// exactly N bytes arrived. This runs as a FRESH exec of this binary.
static int drain_main(const char *expect_s) {
    size_t expect = (size_t) atol(expect_s);
    size_t got = 0;
    unsigned char buf[4096];
    for (;;) {
        ssize_t r = read(STDIN_FILENO, buf, sizeof buf);
        if (r == 0) {
            break;
        }
        if (r < 0) {
            return 42;
        }
        for (ssize_t i = 0; i < r; i++) {
            if ((char) buf[i] != payload_byte(got + (size_t) i)) {
                return 44;
            }
        }
        got += (size_t) r;
    }
    if (got == 0 && expect != 0) {
        return 43; // the live failure: EOF with nothing read
    }
    return got == expect ? 0 : 45;
}

// `--chain N`: exec self AGAIN into `--drain N`. Two execve()s deep — the
// `sh -c 'exec xkbcomp'` shape without needing a shell in the image.
static int chain_main(const char *expect_s) {
    execl(self_path, "popenw", "--drain", expect_s, (char *) 0);
    return 91;
}

// `--chainfork N`: fork a grandchild that execs `--drain N` while this
// (already once-exec'd) process waits — the wrapper-script shape, where
// bash (exec'd by sh -c) forks `cat` to consume stdin. The pipe read end
// on fd 0 is inherited across exec + fork + exec.
static int chainfork_main(const char *expect_s) {
    pid_t g = fork();
    if (g < 0) {
        return 90;
    }
    if (g == 0) {
        execl(self_path, "popenw", "--drain", expect_s, (char *) 0);
        _exit(91);
    }
    int st = 0;
    if (waitpid(g, &st, 0) != g) {
        return 90;
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : 90;
}

// How the consumer reaches the payload. DIRECT/SHELL are the original two
// arms; CHAIN/CHAINFORK are the shell shape decomposed for images with no
// /bin/sh (two execs; two execs + a fork).
enum exec_mode { VIA_DIRECT = 0, VIA_SHELL = 1, VIA_CHAIN = 2, VIA_CHAINFORK = 3 };

// via_shell mirrors X's Popen exactly (`/bin/sh -c`); the direct arm isolates
// whether a plain execve already loses the pipe, so a failure names the layer.
static int exec_round(size_t len, int via_shell, const char *label) {
    // Decide BEFORE opening the pipe. If the exec target is missing, the
    // child exits without ever reading, and a parent that has already
    // committed to writing a payload larger than the pipe buffer blocks
    // against a reader that will never arrive.
    if (via_shell == VIA_SHELL && access("/bin/sh", X_OK) != 0) {
        w("popenw-skip: no /bin/sh for the shell arm (");
        w(label);
        w(")\n");
        return 1;
    }
    if (self_path[0] == 0) {
        w("popenw-skip: self path unknown (");
        w(label);
        w(")\n");
        return 1;
    }
    int p[2];
    if (pipe(p) != 0) {
        w("popenw-fail: exec pipe\n");
        return 0;
    }
    char expect[32];
    snprintf(expect, sizeof expect, "%zu", len);
    pid_t c = fork();
    if (c < 0) {
        w("popenw-fail: exec fork\n");
        return 0;
    }
    if (c == 0) {
        close(p[1]); // drop the inherited writer, as Popen("w") does
        if (dup2(p[0], STDIN_FILENO) < 0) {
            _exit(90);
        }
        close(p[0]);
        switch (via_shell) {
        case VIA_SHELL: {
            char cmd[640];
            snprintf(cmd, sizeof cmd, "exec '%s' --drain %s", self_path, expect);
            execl("/bin/sh", "sh", "-c", cmd, (char *) 0);
            break;
        }
        case VIA_CHAIN:
            execl(self_path, "popenw", "--chain", expect, (char *) 0);
            break;
        case VIA_CHAINFORK:
            execl(self_path, "popenw", "--chainfork", expect, (char *) 0);
            break;
        default:
            execl(self_path, "popenw", "--drain", expect, (char *) 0);
            break;
        }
        _exit(91); // exec itself failed
    }
    close(p[0]);
    size_t sent = 0;
    char chunk[4096];
    while (sent < len) {
        size_t n = len - sent;
        if (n > sizeof chunk) {
            n = sizeof chunk;
        }
        for (size_t i = 0; i < n; i++) {
            chunk[i] = payload_byte(sent + i);
        }
        ssize_t r = write(p[1], chunk, n);
        if (r <= 0) {
            w("popenw-fail: exec write ");
            w(label);
            w("\n");
            close(p[1]);
            waitpid(c, NULL, 0);
            return 0;
        }
        sent += (size_t) r;
    }
    close(p[1]);
    int st = 0;
    if (waitpid(c, &st, 0) != c) {
        w("popenw-fail: exec waitpid\n");
        return 0;
    }
    if (WIFEXITED(st) && WEXITSTATUS(st) == 91) {
        // No shell (or no self path) in this image: report and skip rather
        // than fail, so a missing /bin/sh never masquerades as a pipe bug.
        w("popenw-skip: exec unavailable (");
        w(label);
        w(")\n");
        return 1;
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        if (WIFEXITED(st) && WEXITSTATUS(st) == 43) {
            w("popenw-fail: exec'd consumer read ZERO bytes (");
            w(label);
            w(") — pipe data did not survive execve\n");
        } else {
            w("popenw-fail: exec'd consumer status (");
            w(label);
            w(")\n");
        }
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "--drain") == 0) {
        return drain_main(argv[2]);
    }
    ssize_t n = readlink("/proc/self/exe", self_path, sizeof self_path - 1);
    if (n > 0) {
        self_path[n] = 0;
    } else if (argc >= 1) {
        snprintf(self_path, sizeof self_path, "%s", argv[0]);
    }
    if (argc >= 3 && strcmp(argv[1], "--chain") == 0) {
        return chain_main(argv[2]);
    }
    if (argc >= 3 && strcmp(argv[1], "--chainfork") == 0) {
        return chainfork_main(argv[2]);
    }
    if (!raw_round(SMALL_LEN, 1, "delayed-small")) {
        return 1;
    }
    if (!raw_round(LARGE_LEN, 1, "delayed-large")) {
        return 1;
    }
    if (!stdio_round(LARGE_LEN)) {
        return 1;
    }
    // The X shape: the consumer only exists after execve.
    if (!exec_round(SMALL_LEN, 0, "exec-direct-small")) {
        return 1;
    }
    if (!exec_round(LARGE_LEN, 0, "exec-direct-large")) {
        return 1;
    }
    if (!exec_round(SMALL_LEN, VIA_SHELL, "exec-shell-small")) {
        return 1;
    }
    if (!exec_round(LARGE_LEN, VIA_SHELL, "exec-shell-large")) {
        return 1;
    }
    // The sh -c shape decomposed for shell-less images: the payload must
    // survive TWO execs (writer → sh → xkbcomp)...
    if (!exec_round(SMALL_LEN, VIA_CHAIN, "exec-chain-small")) {
        return 1;
    }
    if (!exec_round(LARGE_LEN, VIA_CHAIN, "exec-chain-large")) {
        return 1;
    }
    // ...and the wrapper-script shape: two execs, then a FORKED grandchild
    // (bash running `cat`) drains the inherited fd 0.
    if (!exec_round(LARGE_LEN, VIA_CHAINFORK, "exec-chainfork-large")) {
        return 1;
    }
    w("popenw-ok\n");
    return 0;
}
