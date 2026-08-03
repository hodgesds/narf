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

int main(void) {
    if (!raw_round(SMALL_LEN, 1, "delayed-small")) {
        return 1;
    }
    if (!raw_round(LARGE_LEN, 1, "delayed-large")) {
        return 1;
    }
    if (!stdio_round(LARGE_LEN)) {
        return 1;
    }
    w("popenw-ok\n");
    return 0;
}
