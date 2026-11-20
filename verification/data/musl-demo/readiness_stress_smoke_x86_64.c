// Lost/late-wakeup and lost-byte stress for the readiness paths a desktop
// session leans on, all running at once on pinned CPUs:
//
//   1. tmux-like relay chains (x3): a "terminal" T writes a checked byte
//      stream into pty A's master; a tmux client C (poll(-1)) relays pty A's
//      slave <-> an AF_UNIX stream socket; a tmux server V (poll(10 ms))
//      relays the socket <-> pty B's master; a fish-like shell F (poll(-1)
//      over the tty, an inotify fd and a SIGCHLD eventfd) echoes every byte,
//      and for every '\r' flips its tty to cooked, forks a command that
//      writes "Z", reaps it from the eventfd wake, flips back to raw, then
//      echoes the '\r'. Bytes typed while cooked sit in the canonical buffer
//      and must become readable when raw is restored (n_tty_set_termios).
//      T checks every returned byte in order ('\r' comes back as "Z\r").
//   2. a systemd-resolved-like epoll_wait(-1) loop R over a unix dgram pair
//      (EPOLLET), a 7 ms timerfd, a SIGUSR1 signalfd, an eventfd, an inotify
//      fd and a UDP socket on [::1]; a driver D fires one stimulus at a time
//      and waits for R's "ack <kind> <seq>".
//   3. a Mesa util_queue-like process Q: glibc mutex + two condvars around a
//      job queue, util_queue_fence raw-futex fences per job, and a Mesa
//      simple_mtx contended by the submitter and two "finisher" threads.
//   4. a Bash-tool-like child-exit loop P: pipe + fork, read to EOF with
//      poll(-1), then reap by waitpid / SIGCHLD+sigsuspend / waitid in turn.
//   5. load: nanosleep and 1 ms timerfd threads, a two-thread mmap/munmap
//      churn (TLB-shootdown IPIs), two spin/sleep hogs, an inotify toucher.
//
// Linux behaviours the protocol is built on (each is something the kernel
// under test must match, not a tolerance):
//   - The parent makes both pty slaves raw before any byte moves (the default
//     ECHO/ICRNL/ONLCR would echo or translate the stream). Masters are raw
//     by default (ptm init_termios) and are never touched: tcsetattr on a
//     master would apply to the slave.
//   - n_tty, raw -> ICANON with unread input: that input becomes a "line"
//     (canon_head = read_head, push = 1), so the slave polls readable while
//     cooked; F therefore leaves the tty out of its poll set while a command
//     runs, as fish does. ICANON -> raw: commit_head = read_head, so input
//     that arrived while cooked is readable at once. With ICRNL/IGNCR/INLCR
//     off and VEOL/VEOL2 disabled, '\r' and 'a'..'y' are ordinary chars.
//   - SIGCHLD is queued once the child is a waitable zombie, so the one
//     eventfd write from F's handler is enough for waitpid(WNOHANG).
//   - The parent keeps a copy of every pty, socket and eventfd, so a dying
//     component never shows up as HUP/EOF at its peers, and the dump can
//     poll them.
//
// Every component bumps a progress counter in one MAP_SHARED page and writes
// a phase word around each blocking call. The parent fails the run when a
// counter stalls for STALL_MS, prints what every process/thread is blocked in
// (phase, /proc state/wchan/syscall) and FIONREAD/poll/fdinfo for every fd,
// SIGKILLs everything and exits 1. It never hangs: alarm(seconds + 30).
//
//   usage:   rstress [seconds [seed]]        (default 240 s)
//   success: readiness-stress-ok chains=3 bytes=... (one line, exit 0)
//   failure: readiness-stress FAIL <component>: <reason>, then a dump
//
// Every assertion is a Linux semantic: it must pass on the host kernel, so a
// failure there means the TEST is wrong. Build: REGEN_readiness_stress_smoke.sh.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

// Linux futex ABI (uapi/linux/futex.h), spelled out so that a libc without
// kernel headers (musl-gcc) builds this too.
#ifndef FUTEX_WAKE
#define FUTEX_WAKE 1
#endif
#ifndef FUTEX_WAIT_BITSET
#define FUTEX_WAIT_BITSET 9
#endif
#ifndef FUTEX_BITSET_MATCH_ANY
#define FUTEX_BITSET_MATCH_ANY 0xffffffffu
#endif

typedef uint64_t u64;
typedef uint32_t u32;
#define U(x) ((unsigned long long)(x))

#define STALL_MS 3000      // no progress for this long = lost wakeup
#define TICK_MS 100        // monitor period
#define NCHAIN 3
#define OUTMAX 256         // terminal bytes in flight per chain
#define TRING 512          // > OUTMAX, power of two
#define LATE_US 100000     // round trip counted as "late"
#define MAXSLOT 48
#define QCAP 8
#define NFENCE 64
#define NWORK 4
#define NFIN 2
#define SPURIOUS_MAX 1000
#define MAXKIDS 32
#define MAXFDL 64

#define LOAD(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define STORE(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define ADD(p, v) __atomic_add_fetch((p), (v), __ATOMIC_ACQ_REL)

enum comp { CP_CHAIN0, CP_CHAIN1, CP_CHAIN2, CP_EPOLL, CP_TIMER, CP_FUTEX, CP_CHILD,
            CP_NMON, CP_LOAD = CP_NMON, CP_SETUP, CP_MONITOR, CP_COUNT };
static const char *const comp_name[CP_COUNT] = {
    "chain1", "chain2", "chain3", "epoll", "timerfd", "futex", "child", "load", "setup", "monitor"};

enum phase { PH_RUN, PH_POLL, PH_READ, PH_WRITE, PH_EPOLL_WAIT, PH_WAITPID, PH_WAITID,
             PH_SIGSUSPEND, PH_FUTEX_FENCE, PH_FUTEX_MTX, PH_COND_JOB, PH_COND_SPACE,
             PH_MUTEX, PH_NANOSLEEP, PH_TCSETATTR, PH_FORK, PH_SEND, PH_YIELD, PH_FAILED,
             PH_COUNT };
static const char *const phase_name[PH_COUNT] = {
    "running", "in_poll", "in_read", "in_write", "in_epoll_wait", "in_waitpid", "in_waitid",
    "in_sigsuspend", "in_futex_wait(fence)", "in_futex_wait(mtx)", "in_cond_wait(has_job)",
    "in_cond_wait(has_space)", "in_mutex_lock", "in_nanosleep", "in_tcsetattr", "in_fork",
    "in_send", "in_sched_yield", "failed(parked)"};

enum stim { ST_UNIX, ST_UDP6, ST_SIG, ST_EFD, ST_INOTIFY, NSTIM };
static const char *const stim_name[NSTIM] = {"unix-dgram", "udp6", "sigusr1", "eventfd", "inotify"};
static const char *const reap_name[3] = {"waitpid", "sigchld+sigsuspend", "waitid"};

// ── shared state (one MAP_SHARED page) ──
struct slot {
    int32_t pid, tid, phase, comp;
    u64 seq; // last sequence number this process/thread handled
    char name[16];
};

struct chain_dbg {
    u64 sent, maxrtt_us, late, cmds, f_inotify;
    int32_t f_cmd_pid, f_cmd_running;
};

struct qstate {
    pthread_mutex_t mtx; // process-private glibc objects; only Q's threads use them
    pthread_cond_t has_job, has_space;
    u32 ring[QCAP], head, tail, count;
    u64 submitted, finishes;
    u64 priv_addr; // where Q mapped its struct qpriv (read with process_vm_readv)
};

// Q's raw futex words live in Q-private anonymous memory, as Mesa's heap
// fences do: the shared (non-PRIVATE) futex op then keys them by mm + address
// like Mesa's, not by the shmem page the rest of the shared state lives in.
struct qpriv {
    u32 finish_lock;   // Mesa simple_mtx: 0 free, 1 locked, 2 locked + waiters
    u32 fence[NFENCE]; // util_queue_fence: 0 signalled, 1 unsignalled, 2 + waiters
};
static struct qpriv *qp;

struct shared {
    int fail; // 0; 1 = claimed; 2 = reason published
    int fail_comp, fail_slot, stopping, pin_fail, nslots;
    char reason[400];
    u64 progress[CP_COUNT];
    struct slot slot[MAXSLOT];
    struct chain_dbg ch[NCHAIN];
    u32 stim_kind;
    int32_t p_pid, p_method;
    u64 stim_seq, stim_t_ms, acked_seq, r_seen[NSTIM], r_useless_max;
    struct qstate q;
};
_Static_assert(sizeof(struct shared) <= 4096, "shared state must fit one page");

static struct shared *sh;

// Parent-created state, inherited by every child through fork().
static struct {
    int am[NCHAIN], as[NCHAIN], bm[NCHAIN], bs[NCHAIN];
    char aname[NCHAIN][64], bname[NCHAIN][64];
    int sk[NCHAIN][2]; // [0] = C's end, [1] = V's end
    int f_ino[NCHAIN], f_efd[NCHAIN];
    int r_dg[2], r_ack[2]; // [0] = R's end, [1] = D's end
    int r_tfd, r_efd, r_ino, r_ep, u6rx, u6tx, ipv6;
    pid_t r_pid, monitor, pgid;
    char base[64], fishdir[96], resdir[96];
    int cpus[CPU_SETSIZE], ncpus;
    u64 seed;
} g;

static struct { int fd; char label[32]; } fdl[MAXFDL];
static int nfdl;
static struct { pid_t pid; int slot, alive; } kids[MAXKIDS];
static int nkids;

static __thread int me = -1;
static __thread u64 rng;

static u64 rnd(void) {
    rng ^= rng >> 12;
    rng ^= rng << 25;
    rng ^= rng >> 27;
    return rng * 2685821657736338717ULL;
}

static void ph(int p) {
    if (me >= 0)
        __atomic_store_n(&sh->slot[me].phase, p, __ATOMIC_RELAXED);
}

// Bracket one blocking call with the phase word: n = BLOCKING(PH_POLL, poll(..)).
// errno survives (ph is a plain atomic store).
#define BLOCKING(phase, call)                                                                  \
    ({                                                                                         \
        ph(phase);                                                                             \
        __typeof__(call) _b = (call);                                                          \
        ph(PH_RUN);                                                                            \
        _b;                                                                                    \
    })

static void seq_set(u64 v) {
    if (me >= 0)
        __atomic_store_n(&sh->slot[me].seq, v, __ATOMIC_RELAXED);
}

static u64 now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000u + (u64)ts.tv_nsec / 1000u;
}
static u64 now_ms(void) { return now_us() / 1000u; }

static void sleep_us(u64 us) {
    struct timespec ts = {(time_t)(us / 1000000u), (long)(us % 1000000u) * 1000};
    while (clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, &ts) == EINTR)
        ;
}

static void nap(u64 us) {
    ph(PH_NANOSLEEP);
    sleep_us(us);
    ph(PH_RUN);
}

static void kill_all(int sig) {
    if (g.pgid > 0)
        kill(-g.pgid, sig);
    for (int i = 0; i < nkids; i++)
        if (kids[i].alive)
            kill(kids[i].pid, sig);
}

// Reap children (and grandchildren reparented to us) for up to budget_ms.
static void reap_all(u64 budget_ms) {
    u64 end = now_ms() + budget_ms;
    for (;;) {
        int st;
        pid_t r = waitpid(-1, &st, WNOHANG);
        if (r > 0) {
            for (int i = 0; i < nkids; i++)
                if (kids[i].pid == r)
                    kids[i].alive = 0;
            continue;
        }
        if (r < 0 && errno == ECHILD)
            return;
        if (now_ms() >= end)
            return;
        sleep_us(5000);
    }
}

static void rm_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.')
                continue;
            char p[512];
            snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(dir);
}

static void cleanup_dirs(void) {
    if (!g.base[0])
        return;
    rm_dir(g.fishdir);
    rm_dir(g.resdir);
    rmdir(g.base);
}

// Record the first failure. Returns 1 when this call won the race.
static int vclaim(int comp, const char *fmt, va_list ap) {
    int expect = 0;
    if (LOAD(&sh->stopping))
        return 0;
    if (!__atomic_compare_exchange_n(&sh->fail, &expect, 1, 0, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE))
        return 0;
    vsnprintf(sh->reason, sizeof sh->reason, fmt, ap);
    sh->fail_comp = comp;
    sh->fail_slot = me;
    STORE(&sh->fail, 2);
    return 1;
}

// Component failure: publish the reason, then park until the monitor kills
// us (exiting would close fds and change what the dump sees). In the parent
// (setup, before any child runs) it reports and exits directly.
static void __attribute__((noreturn, format(printf, 2, 3))) cfail(int comp, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (getpid() == g.monitor) {
        printf("readiness-stress FAIL %s: ", comp_name[comp]);
        vprintf(fmt, ap);
        printf("\n");
        fflush(stdout);
        kill_all(SIGKILL);
        reap_all(2000);
        cleanup_dirs();
        exit(1);
    }
    vclaim(comp, fmt, ap);
    va_end(ap);
    ph(PH_FAILED);
    for (;;)
        pause();
}

static void __attribute__((format(printf, 2, 3))) mfail(int comp, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vclaim(comp, fmt, ap);
    va_end(ap);
}

#define CK(comp, expr, what)                                                                   \
    ({                                                                                         \
        __typeof__(expr) _r = (expr);                                                          \
        if (_r < 0)                                                                            \
            cfail((comp), "%s: %s", (what), strerror(errno));                                 \
        _r;                                                                                    \
    })

static const char *revstr(int r, char *buf, size_t n) {
    static const struct { int bit; const char *name; } t[] = {
        {POLLIN, "POLLIN"},   {POLLPRI, "POLLPRI"},   {POLLOUT, "POLLOUT"},    {POLLERR, "POLLERR"},
        {POLLHUP, "POLLHUP"}, {POLLNVAL, "POLLNVAL"}, {POLLRDHUP, "POLLRDHUP"}};
    size_t o = 0;
    buf[0] = 0;
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
        if ((r & t[i].bit) && o < n)
            o += (size_t)snprintf(buf + o, n - o, "%s%s", o ? "|" : "", t[i].name);
    if (!o)
        snprintf(buf, n, "0");
    return buf;
}

static const char *bdesc(uint8_t c, char *buf) {
    if (c == '\r')
        return "'\\r'";
    if (c >= 0x20 && c < 0x7f)
        snprintf(buf, 8, "'%c'", c);
    else
        snprintf(buf, 8, "0x%02x", c);
    return buf;
}

static int slot_alloc(const char *name, int comp) {
    int s = __atomic_fetch_add(&sh->nslots, 1, __ATOMIC_ACQ_REL);
    if (s >= MAXSLOT)
        cfail(CP_SETUP, "out of process slots (%d)", MAXSLOT);
    snprintf(sh->slot[s].name, sizeof sh->slot[s].name, "%s", name);
    sh->slot[s].comp = comp;
    return s;
}

// Run by the process/thread that owns slot s: identify, pin, seed.
static void slot_enter(int s) {
    me = s;
    STORE(&sh->slot[s].pid, (int32_t)getpid());
    STORE(&sh->slot[s].tid, (int32_t)syscall(SYS_gettid));
    rng = (g.seed ^ ((u64)(s + 1) * 0x9E3779B97F4A7C15ULL)) | 1;
    for (int i = 0; i < 8; i++)
        rnd();
    if (g.ncpus > 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(g.cpus[s % g.ncpus], &set);
        if (sched_setaffinity(0, sizeof set, &set) < 0)
            ADD(&sh->pin_fail, 1);
    }
    ph(PH_RUN);
}

static void set_nonblock(int comp, int fd, const char *what) {
    int fl = CK(comp, fcntl(fd, F_GETFL), what);
    CK(comp, fcntl(fd, F_SETFL, fl | O_NONBLOCK), what);
}

static void tty_set(int comp, int fd, const struct termios *t, const char *what) {
    ph(PH_TCSETATTR);
    while (tcsetattr(fd, TCSANOW, t) < 0)
        if (errno != EINTR)
            cfail(comp, "tcsetattr(%s): %s", what, strerror(errno));
    ph(PH_RUN);
}

static void tty_raw(int comp, int fd, const char *what) {
    struct termios t;
    CK(comp, tcgetattr(fd, &t), what);
    cfmakeraw(&t);
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    tty_set(comp, fd, &t, what);
}

// fish running a command: canonical, no echo/signals/flow control, no CR
// mapping (so '\r' is an ordinary char, not a line end), OPOST without ONLCR.
static void tty_cooked_noecho(int comp, int fd) {
    struct termios t;
    CK(comp, tcgetattr(fd, &t), "F tcgetattr(B_s)");
    t.c_iflag = 0;
    t.c_oflag = OPOST;
    t.c_lflag = ICANON;
    t.c_cflag = (t.c_cflag & ~(tcflag_t)(CSIZE | PARENB)) | CS8 | CREAD;
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    tty_set(comp, fd, &t, "F B_s cooked");
}

static void write_all(int comp, int fd, const void *buf, size_t len, const char *what) {
    const uint8_t *p = buf;
    while (len) {
        ssize_t w = BLOCKING(PH_WRITE, write(fd, p, len));
        if (w < 0) {
            if (errno == EINTR)
                continue;
            cfail(comp, "%s: %s", what, strerror(errno));
        }
        p += w;
        len -= (size_t)w;
    }
}

static void check_revents(int comp, const char *who, const char *fdname, int rev) {
    if (rev & (POLLERR | POLLHUP | POLLNVAL)) {
        char rb[64];
        cfail(comp, "%s poll(%s) revents=%s", who, fdname, revstr(rev, rb, sizeof rb));
    }
}

// ── 1. relay chains ─────────────────────────────────────────────────────

// T: the terminal emulator. Writes a PRNG stream ('a'..'y' plus a '\r'
// every 8-20 bytes) into pty A's master, at most OUTMAX bytes in flight, and
// checks the echo exactly: c -> c, '\r' -> "Z\r".
static void run_terminal(int k) {
    int comp = CP_CHAIN0 + k, fd = g.am[k];
    struct chain_dbg *d = &sh->ch[k];
    uint8_t ring[TRING];
    u64 ts[TRING];
    u64 gen = 0, sent = 0, ver = 0;
    int zseen = 0, countdown = 8 + (int)(rnd() % 13);
    set_nonblock(comp, fd, "T fcntl(A_m)");
    for (;;) {
        int can_write = sent - ver < OUTMAX;
        struct pollfd p = {fd, (short)(POLLIN | (can_write ? POLLOUT : 0)), 0};
        int n = BLOCKING(PH_POLL, poll(&p, 1, 100));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            cfail(comp, "T poll(A_m): %s", strerror(errno));
        }
        if (n == 0)
            continue;
        check_revents(comp, "T", "A_m", p.revents);
        if (p.revents & POLLIN) {
            uint8_t buf[TRING];
            ssize_t r = BLOCKING(PH_READ, read(fd, buf, sizeof buf));
            if (r < 0 && errno != EAGAIN && errno != EINTR)
                cfail(comp, "T read(A_m): %s", strerror(errno));
            if (r == 0)
                cfail(comp, "T read(A_m): EOF");
            for (ssize_t i = 0; i < r; i++) {
                uint8_t got = buf[i], exp;
                char b1[8], b2[8];
                if (ver == sent)
                    cfail(comp, "unexpected byte %s at seq %llu: nothing outstanding",
                          bdesc(got, b1), U(ver));
                exp = ring[ver % TRING];
                if (exp == '\r' && !zseen) {
                    if (got != 'Z')
                        cfail(comp, "lost/reordered byte at seq %llu: expected 'Z' (output of "
                              "the command run for '\\r') got %s", U(ver), bdesc(got, b2));
                    zseen = 1;
                    continue;
                }
                if (got != exp)
                    cfail(comp, "lost/reordered byte at seq %llu: expected %s got %s", U(ver),
                          bdesc(exp, b1), bdesc(got, b2));
                zseen = 0;
                u64 rtt = now_us() - ts[ver % TRING];
                if (rtt > d->maxrtt_us)
                    STORE(&d->maxrtt_us, rtt);
                if (rtt > LATE_US)
                    ADD(&d->late, 1);
                ver++;
            }
            STORE(&sh->progress[comp], ver);
            seq_set(ver);
        }
        if ((p.revents & POLLOUT) && sent - ver < OUTMAX) {
            u64 want = sent + 1 + rnd() % 64;
            if (want > ver + OUTMAX)
                want = ver + OUTMAX;
            for (; gen < want; gen++) {
                if (countdown-- == 0) {
                    ring[gen % TRING] = '\r';
                    countdown = 8 + (int)(rnd() % 13);
                } else {
                    ring[gen % TRING] = (uint8_t)('a' + rnd() % 25);
                }
            }
            size_t off = sent % TRING, len = (size_t)(gen - sent);
            if (off + len > TRING)
                len = TRING - off;
            ssize_t w = BLOCKING(PH_WRITE, write(fd, ring + off, len));
            if (w < 0) {
                if (errno != EAGAIN && errno != EINTR)
                    cfail(comp, "T write(A_m): %s", strerror(errno));
            } else {
                u64 t = now_us();
                for (ssize_t j = 0; j < w; j++)
                    ts[(sent + (u64)j) % TRING] = t;
                sent += (u64)w;
                STORE(&d->sent, sent);
            }
        }
    }
}

struct pbuf { uint8_t d[4096]; size_t off, len; };

static void pb_fill(int comp, const char *who, int fd, struct pbuf *b) {
    if (b->off) {
        memmove(b->d, b->d + b->off, b->len);
        b->off = 0;
    }
    if (b->len == sizeof b->d)
        return;
    ssize_t r = BLOCKING(PH_READ, read(fd, b->d + b->len, sizeof b->d - b->len));
    if (r < 0) {
        if (errno == EAGAIN || errno == EINTR)
            return;
        cfail(comp, "%s read: %s", who, strerror(errno));
    }
    if (r == 0)
        cfail(comp, "%s read: unexpected EOF", who);
    b->len += (size_t)r;
}

static u64 pb_drain(int comp, const char *who, int fd, struct pbuf *b) {
    ssize_t w = BLOCKING(PH_WRITE, write(fd, b->d + b->off, b->len));
    if (w < 0) {
        if (errno == EAGAIN || errno == EINTR)
            return 0;
        cfail(comp, "%s write: %s", who, strerror(errno));
    }
    b->off += (size_t)w;
    b->len -= (size_t)w;
    if (!b->len)
        b->off = 0;
    return (u64)w;
}

// libevent/tmux-style relay a <-> b: userspace pending buffers, nonblocking
// fds, POLLOUT requested only on the fd that has pending data, writes only
// on POLLOUT.
static void relay(int comp, const char *self, int a, const char *an, int b, const char *bn,
                  int timeout) {
    struct pbuf to_a = {.len = 0}, to_b = {.len = 0};
    char wa[32], wb[32];
    u64 moved = 0;
    snprintf(wa, sizeof wa, "%s %s", self, an);
    snprintf(wb, sizeof wb, "%s %s", self, bn);
    for (;;) {
        struct pollfd p[2] = {
            {a, (short)((to_b.len < sizeof to_b.d ? POLLIN : 0) | (to_a.len ? POLLOUT : 0)), 0},
            {b, (short)((to_a.len < sizeof to_a.d ? POLLIN : 0) | (to_b.len ? POLLOUT : 0)), 0}};
        int n = BLOCKING(PH_POLL, poll(p, 2, timeout));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            cfail(comp, "%s poll: %s", self, strerror(errno));
        }
        if (n == 0)
            continue;
        check_revents(comp, self, an, p[0].revents);
        check_revents(comp, self, bn, p[1].revents);
        if (p[0].revents & POLLIN)
            pb_fill(comp, wa, a, &to_b);
        if (p[1].revents & POLLIN)
            pb_fill(comp, wb, b, &to_a);
        if ((p[1].revents & POLLOUT) && to_b.len)
            moved += pb_drain(comp, wb, b, &to_b);
        if ((p[0].revents & POLLOUT) && to_a.len)
            moved += pb_drain(comp, wa, a, &to_a);
        seq_set(moved);
    }
}

// C: tmux client. pty A slave <-> socket, poll(-1).
static void run_client(int k) {
    int comp = CP_CHAIN0 + k;
    int fd = CK(comp, open(g.aname[k], O_RDWR | O_NOCTTY | O_NONBLOCK), "C open(A_s)");
    tty_raw(comp, fd, "C A_s raw");
    set_nonblock(comp, g.sk[k][0], "C fcntl(sock)");
    relay(comp, "C", fd, "A_s", g.sk[k][0], "sock", -1);
}

// V: tmux server. socket <-> pty B master, poll(10 ms).
static void run_server(int k) {
    int comp = CP_CHAIN0 + k;
    set_nonblock(comp, g.bm[k], "V fcntl(B_m)");
    set_nonblock(comp, g.sk[k][1], "V fcntl(sock)");
    relay(comp, "V", g.bm[k], "B_m", g.sk[k][1], "sock", 10);
}

static int f_efd = -1;
static void f_sigchld(int s) {
    (void)s;
    int e = errno;
    u64 one = 1;
    if (write(f_efd, &one, sizeof one) < 0) {
        // EAGAIN only on counter overflow; the reader drains it on every wake.
    }
    errno = e;
}

static void drain_inotify(int comp, int fd, u64 *count) {
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    for (;;) {
        ssize_t r = read(fd, buf, sizeof buf);
        if (r < 0) {
            if (errno == EAGAIN)
                return;
            if (errno == EINTR)
                continue;
            cfail(comp, "F read(inotify): %s", strerror(errno));
        }
        if (r == 0)
            cfail(comp, "F read(inotify) returned 0");
        for (char *p = buf; p < buf + r;) {
            struct inotify_event *ie = (struct inotify_event *)p;
            if (ie->mask & IN_Q_OVERFLOW)
                cfail(comp, "F inotify queue overflowed: reader starved of wakeups");
            p += sizeof *ie + ie->len;
            (*count)++;
        }
    }
}

// F: fish. Echoes input; runs a "command" for every '\r' with the tty cooked.
static void run_fish(int k) {
    int comp = CP_CHAIN0 + k;
    struct chain_dbg *d = &sh->ch[k];
    int fd = CK(comp, open(g.bname[k], O_RDWR | O_NOCTTY), "F open(B_s)");
    tty_raw(comp, fd, "F B_s raw");
    f_efd = g.f_efd[k];
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = f_sigchld;
    sa.sa_flags = SA_NOCLDSTOP; // no SA_RESTART: poll sees EINTR and loops
    sigemptyset(&sa.sa_mask);
    CK(comp, sigaction(SIGCHLD, &sa, NULL), "F sigaction(SIGCHLD)");
    uint8_t back[1024]; // input read but not yet processed
    size_t boff = 0, blen = 0;
    pid_t cpid = -1;
    u64 processed = 0, ino = 0;
    for (;;) {
        if (cpid < 0 && blen) {
            size_t n = 0;
            while (n < blen && back[boff + n] != '\r')
                n++;
            if (n) {
                write_all(comp, fd, back + boff, n, "F echo write(B_s)");
                boff += n;
                blen -= n;
                processed += n;
            }
            if (blen) { // back[boff] == '\r': run a command with the tty cooked
                boff++;
                blen--;
                processed++;
                tty_cooked_noecho(comp, fd);
                pid_t c = BLOCKING(PH_FORK, fork());
                if (c < 0)
                    cfail(comp, "F fork: %s", strerror(errno));
                if (c == 0) {
                    ssize_t w = write(fd, "Z", 1);
                    _exit(w == 1 ? 0 : 3);
                }
                cpid = c;
                STORE(&d->f_cmd_pid, (int32_t)c);
                STORE(&d->f_cmd_running, 1);
                ADD(&d->cmds, 1);
            }
            if (!blen)
                boff = 0;
            seq_set(processed);
            continue;
        }
        // While the command runs fish does not touch the tty.
        struct pollfd p[3] = {
            {cpid < 0 ? fd : -1, POLLIN, 0}, {g.f_ino[k], POLLIN, 0}, {f_efd, POLLIN, 0}};
        int n = BLOCKING(PH_POLL, poll(p, 3, -1));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            cfail(comp, "F poll: %s", strerror(errno));
        }
        check_revents(comp, "F", "B_s", p[0].revents);
        check_revents(comp, "F", "inotify", p[1].revents);
        check_revents(comp, "F", "eventfd", p[2].revents);
        if (p[1].revents & POLLIN) {
            drain_inotify(comp, g.f_ino[k], &ino);
            STORE(&d->f_inotify, ino);
        }
        if (p[2].revents & POLLIN) {
            u64 v;
            if (read(f_efd, &v, sizeof v) < 0 && errno != EAGAIN && errno != EINTR)
                cfail(comp, "F read(eventfd): %s", strerror(errno));
            for (;;) {
                int st;
                pid_t w = BLOCKING(PH_WAITPID, waitpid(-1, &st, WNOHANG));
                if (w == 0)
                    break;
                if (w < 0) {
                    if (errno == EINTR)
                        continue;
                    if (errno == ECHILD)
                        break;
                    cfail(comp, "F waitpid: %s", strerror(errno));
                }
                if (w != cpid)
                    cfail(comp, "F reaped unexpected child %d (command is %d)", w, cpid);
                if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
                    cfail(comp, "F command %d ended with status 0x%x (its write of \"Z\" failed)",
                          w, st);
                cpid = -1;
                STORE(&d->f_cmd_running, 0);
                tty_raw(comp, fd, "F B_s raw");
                write_all(comp, fd, "\r", 1, "F echo write(B_s)");
            }
        }
        if (p[0].revents & POLLIN) {
            ssize_t r = BLOCKING(PH_READ, read(fd, back, sizeof back));
            if (r < 0) {
                if (errno == EINTR || errno == EAGAIN)
                    continue;
                cfail(comp, "F read(B_s): %s", strerror(errno));
            }
            if (r == 0)
                cfail(comp, "F read(B_s): EOF");
            boff = 0;
            blen = (size_t)r;
        }
    }
}

// ── 2. epoll (resolved R + driver D) ─────────────────────────────────────

enum { EV_UNIX = 1, EV_TIMER, EV_SIG, EV_EFD, EV_INO, EV_UDP6 };

static void r_ack(int kind, u64 seq) {
    char m[64];
    int n = snprintf(m, sizeof m, "ack %s %llu", stim_name[kind], U(seq));
    ssize_t w;
    ph(PH_SEND);
    do
        w = send(g.r_ack[0], m, (size_t)n, 0);
    while (w < 0 && errno == EINTR);
    ph(PH_RUN);
    if (w != n)
        cfail(CP_EPOLL, "R send(ack): %s", w < 0 ? strerror(errno) : "short");
    ADD(&sh->r_seen[kind], 1);
    seq_set(seq);
}

static void r_expect(int kind, u64 seq) {
    u32 k = LOAD(&sh->stim_kind);
    u64 s = LOAD(&sh->stim_seq);
    if ((int)k != kind || s != seq)
        cfail(CP_EPOLL, "R saw %s seq=%llu but the outstanding stimulus is %s seq=%llu "
              "(spurious or duplicated event)", stim_name[kind], U(seq), stim_name[k], U(s));
}

// Handle one epoll event; returns 1 if it yielded something to consume.
static int r_handle(u64 tag, u32 events, int sfd) {
    int used = 0;
    if (events & (EPOLLERR | EPOLLHUP))
        cfail(CP_EPOLL, "R epoll event tag=%llu events=0x%x (ERR/HUP)", U(tag), events);
    switch (tag) {
    case EV_UNIX: // EPOLLET: drain completely
        for (;;) {
            char b[64];
            u64 s;
            ssize_t r = recv(g.r_dg[0], b, sizeof b - 1, MSG_DONTWAIT);
            if (r < 0) {
                if (errno == EAGAIN)
                    break;
                if (errno == EINTR)
                    continue;
                cfail(CP_EPOLL, "R recv(unix dgram): %s", strerror(errno));
            }
            b[r] = 0;
            if (sscanf(b, "u %llu", (unsigned long long *)&s) != 1)
                cfail(CP_EPOLL, "R unix dgram: garbage \"%s\"", b);
            r_expect(ST_UNIX, s);
            r_ack(ST_UNIX, s);
            used = 1;
        }
        break;
    case EV_UDP6: {
        char b[64];
        u64 s;
        ssize_t r = recv(g.u6rx, b, sizeof b - 1, MSG_DONTWAIT);
        if (r < 0) {
            if (errno != EAGAIN && errno != EINTR)
                cfail(CP_EPOLL, "R recv(udp6): %s", strerror(errno));
            break;
        }
        b[r] = 0;
        if (sscanf(b, "6 %llu", (unsigned long long *)&s) != 1)
            cfail(CP_EPOLL, "R udp6: garbage \"%s\"", b);
        r_expect(ST_UDP6, s);
        r_ack(ST_UDP6, s);
        used = 1;
        break;
    }
    case EV_TIMER: {
        u64 v;
        ssize_t r = read(g.r_tfd, &v, sizeof v);
        if (r < 0) {
            if (errno != EAGAIN && errno != EINTR)
                cfail(CP_TIMER, "R read(timerfd): %s", strerror(errno));
            break;
        }
        if (r != sizeof v || v == 0)
            cfail(CP_TIMER, "R read(timerfd) = %zd, expirations %llu", r, U(v));
        ADD(&sh->progress[CP_TIMER], v);
        used = 1;
        break;
    }
    case EV_SIG:
        for (;;) {
            struct signalfd_siginfo si;
            ssize_t r = read(sfd, &si, sizeof si);
            if (r < 0) {
                if (errno == EAGAIN)
                    break;
                if (errno == EINTR)
                    continue;
                cfail(CP_EPOLL, "R read(signalfd): %s", strerror(errno));
            }
            if (r != sizeof si || si.ssi_signo != SIGUSR1)
                cfail(CP_EPOLL, "R signalfd: read %zd, signo %u", r, si.ssi_signo);
            u64 s = LOAD(&sh->stim_seq);
            r_expect(ST_SIG, s);
            r_ack(ST_SIG, s);
            used = 1;
        }
        break;
    case EV_EFD: {
        u64 v;
        ssize_t r = read(g.r_efd, &v, sizeof v);
        if (r < 0) {
            if (errno != EAGAIN && errno != EINTR)
                cfail(CP_EPOLL, "R read(eventfd): %s", strerror(errno));
            break;
        }
        if (v != 1)
            cfail(CP_EPOLL, "R eventfd count %llu, expected 1 (one stimulus in flight)", U(v));
        u64 s = LOAD(&sh->stim_seq);
        r_expect(ST_EFD, s);
        r_ack(ST_EFD, s);
        used = 1;
        break;
    }
    case EV_INO:
        for (;;) {
            char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
            ssize_t r = read(g.r_ino, buf, sizeof buf);
            if (r < 0) {
                if (errno == EAGAIN)
                    break;
                if (errno == EINTR)
                    continue;
                cfail(CP_EPOLL, "R read(inotify): %s", strerror(errno));
            }
            for (char *p = buf; p < buf + r;) {
                struct inotify_event *ie = (struct inotify_event *)p;
                u64 s;
                p += sizeof *ie + ie->len;
                if (!(ie->mask & IN_CREATE) || !ie->len ||
                    sscanf(ie->name, "s%llu", (unsigned long long *)&s) != 1)
                    cfail(CP_EPOLL, "R inotify: unexpected event mask=0x%x name=\"%s\"",
                          ie->mask, ie->len ? ie->name : "");
                r_expect(ST_INOTIFY, s);
                r_ack(ST_INOTIFY, s);
                used = 1;
            }
        }
        break;
    default:
        cfail(CP_EPOLL, "R epoll returned unknown tag %llu", U(tag));
    }
    return used;
}

static void ep_add(int fd, u32 events, u64 tag, const char *what) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = events;
    ev.data.u64 = tag;
    CK(CP_EPOLL, epoll_ctl(g.r_ep, EPOLL_CTL_ADD, fd, &ev), what);
}

static void run_resolved(int unused) {
    (void)unused;
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1); // already blocked since the parent; signalfd needs it
    CK(CP_EPOLL, sigprocmask(SIG_BLOCK, &m, NULL), "R sigprocmask");
    int sfd = CK(CP_EPOLL, signalfd(-1, &m, SFD_NONBLOCK), "R signalfd");
    struct itimerspec its = {{0, 7000000}, {0, 7000000}};
    CK(CP_TIMER, timerfd_settime(g.r_tfd, 0, &its, NULL), "R timerfd_settime");
    ep_add(g.r_dg[0], EPOLLIN | EPOLLET, EV_UNIX, "R epoll_ctl(unix dgram)");
    ep_add(g.r_tfd, EPOLLIN, EV_TIMER, "R epoll_ctl(timerfd)");
    ep_add(sfd, EPOLLIN, EV_SIG, "R epoll_ctl(signalfd)");
    ep_add(g.r_efd, EPOLLIN, EV_EFD, "R epoll_ctl(eventfd)");
    ep_add(g.r_ino, EPOLLIN, EV_INO, "R epoll_ctl(inotify)");
    if (g.ipv6)
        ep_add(g.u6rx, EPOLLIN, EV_UDP6, "R epoll_ctl(udp6)");
    u64 useless = 0;
    for (;;) {
        struct epoll_event ev[16];
        int n = BLOCKING(PH_EPOLL_WAIT, epoll_wait(g.r_ep, ev, 16, -1));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            cfail(CP_EPOLL, "R epoll_wait: %s", strerror(errno));
        }
        int used = 0;
        for (int i = 0; i < n; i++)
            used |= r_handle(ev[i].data.u64, ev[i].events, sfd);
        if (used) {
            useless = 0;
            continue;
        }
        if (++useless > sh->r_useless_max)
            STORE(&sh->r_useless_max, useless);
        if (useless > SPURIOUS_MAX)
            cfail(CP_EPOLL, "epoll_wait(-1) returned %llu times in a row with nothing to "
                  "consume (spurious-wake livelock; last n=%d)", U(useless), n);
    }
}

static void run_driver(int unused) {
    (void)unused;
    int kinds[NSTIM], nk = 0;
    for (int k = 0; k < NSTIM; k++)
        if (k != ST_UDP6 || g.ipv6)
            kinds[nk++] = k;
    for (u64 seq = 1;; seq++) {
        int kind = kinds[rnd() % (u64)nk];
        char m[48], path[160] = "", want[64], got[64];
        int n;
        STORE(&sh->stim_seq, seq);
        STORE(&sh->stim_t_ms, now_ms());
        STORE(&sh->stim_kind, (u32)kind);
        seq_set(seq);
        ph(PH_SEND);
        switch (kind) {
        case ST_UNIX:
            n = snprintf(m, sizeof m, "u %llu", U(seq));
            if (send(g.r_dg[1], m, (size_t)n, 0) != n)
                cfail(CP_EPOLL, "D send(unix dgram): %s", strerror(errno));
            break;
        case ST_UDP6:
            n = snprintf(m, sizeof m, "6 %llu", U(seq));
            if (send(g.u6tx, m, (size_t)n, 0) != n)
                cfail(CP_EPOLL, "D send(udp6): %s", strerror(errno));
            break;
        case ST_SIG:
            CK(CP_EPOLL, kill(g.r_pid, SIGUSR1), "D kill(R, SIGUSR1)");
            break;
        case ST_EFD: {
            u64 one = 1;
            if (write(g.r_efd, &one, sizeof one) != sizeof one)
                cfail(CP_EPOLL, "D write(eventfd): %s", strerror(errno));
            break;
        }
        case ST_INOTIFY: {
            snprintf(path, sizeof path, "%s/s%llu", g.resdir, U(seq));
            int fd = CK(CP_EPOLL, open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600),
                        "D create inotify file");
            close(fd);
            break;
        }
        }
        ph(PH_RUN);
        int wn = snprintf(want, sizeof want, "ack %s %llu", stim_name[kind], U(seq));
        u64 deadline = now_ms() + STALL_MS;
        for (;;) {
            u64 t = now_ms();
            if (t >= deadline) {
                ssize_t pk = recv(g.r_ack[1], got, sizeof got, MSG_DONTWAIT | MSG_PEEK);
                if (pk > 0)
                    cfail(CP_EPOLL, "poll lost wakeup on D's ack socket: the ack for %s seq=%llu "
                          "is queued but poll(POLLIN) timed out after %d ms",
                          stim_name[kind], U(seq), STALL_MS);
                cfail(CP_EPOLL, "epoll lost wakeup: %s seq=%llu not acked by R within %d ms",
                      stim_name[kind], U(seq), STALL_MS);
            }
            struct pollfd p = {g.r_ack[1], POLLIN, 0};
            int r = BLOCKING(PH_POLL, poll(&p, 1, (int)(deadline - t)));
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                cfail(CP_EPOLL, "D poll(ack): %s", strerror(errno));
            }
            if (r == 0)
                continue;
            check_revents(CP_EPOLL, "D", "ack", p.revents);
            break;
        }
        ssize_t r = recv(g.r_ack[1], got, sizeof got - 1, MSG_DONTWAIT);
        if (r < 0)
            cfail(CP_EPOLL, "D recv(ack) after POLLIN: %s", strerror(errno));
        got[r] = 0;
        if (r != wn || memcmp(got, want, (size_t)wn) != 0)
            cfail(CP_EPOLL, "D expected \"%s\" got \"%s\"", want, got);
        STORE(&sh->acked_seq, seq);
        ADD(&sh->progress[CP_EPOLL], 1);
        if (kind == ST_INOTIFY)
            CK(CP_EPOLL, unlink(path), "D unlink inotify file");
        if (rnd() % 4 == 0) { // let R park in epoll_wait before the next stimulus
            nap(rnd() % 2000);
        }
    }
}

// ── 3. util_queue (futex fences + simple_mtx + glibc condvars) ───────────

static void futex_wait(u32 *a, u32 v) {
    // Mesa: FUTEX_WAIT_BITSET + MATCH_ANY (absolute timeout form), shared op.
    if (syscall(SYS_futex, a, FUTEX_WAIT_BITSET, v, NULL, NULL, FUTEX_BITSET_MATCH_ANY) < 0 &&
        errno != EAGAIN && errno != EINTR)
        cfail(CP_FUTEX, "futex(FUTEX_WAIT_BITSET): %s", strerror(errno));
}

static void futex_wake(u32 *a, int n) {
    if (syscall(SYS_futex, a, FUTEX_WAKE, n, NULL, NULL, 0) < 0)
        cfail(CP_FUTEX, "futex(FUTEX_WAKE): %s", strerror(errno));
}

// util_queue_fence_signal
static void fence_signal(u32 *f) {
    u32 v = __atomic_exchange_n(f, 0, __ATOMIC_ACQ_REL);
    if (v == 0)
        cfail(CP_FUTEX, "fence %d signalled twice", (int)(f - qp->fence));
    if (v == 2)
        futex_wake(f, INT_MAX);
}

// _util_queue_fence_wait; returns 1 if the fence was unsignalled on entry.
static int fence_wait(u32 *f) {
    u32 v = __atomic_load_n(f, __ATOMIC_RELAXED);
    if (v == 0)
        return 0;
    ph(PH_FUTEX_FENCE);
    do {
        if (v != 2) {
            u32 exp = 1;
            __atomic_compare_exchange_n(f, &exp, 2, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
            v = exp; // old value
            if (v == 0)
                break;
        }
        futex_wait(f, 2);
        v = __atomic_load_n(f, __ATOMIC_ACQUIRE);
    } while (v != 0);
    ph(PH_RUN);
    return 1;
}

// Mesa simple_mtx
static void simple_mtx_lock(u32 *m) {
    u32 c = 0;
    ph(PH_FUTEX_MTX);
    __atomic_compare_exchange_n(m, &c, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    if (c != 0) {
        if (c != 2)
            c = __atomic_exchange_n(m, 2, __ATOMIC_ACQ_REL);
        while (c != 0) {
            futex_wait(m, 2);
            c = __atomic_exchange_n(m, 2, __ATOMIC_ACQ_REL);
        }
    }
    ph(PH_RUN);
}

static void simple_mtx_unlock(u32 *m) {
    if (__atomic_fetch_sub(m, 1, __ATOMIC_ACQ_REL) != 1) {
        __atomic_store_n(m, 0, __ATOMIC_RELEASE);
        futex_wake(m, 1);
    }
}

static void q_lock(void) {
    int e = BLOCKING(PH_MUTEX, pthread_mutex_lock(&sh->q.mtx));
    if (e)
        cfail(CP_FUTEX, "pthread_mutex_lock: %s", strerror(e));
}

static void q_cond_wait(pthread_cond_t *c, int phase) {
    ph(phase);
    int e = pthread_cond_wait(c, &sh->q.mtx);
    ph(PH_RUN);
    if (e)
        cfail(CP_FUTEX, "pthread_cond_wait: %s", strerror(e));
}

static void q_worker(void) {
    struct qstate *q = &sh->q;
    for (;;) {
        q_lock();
        while (q->count == 0)
            q_cond_wait(&q->has_job, PH_COND_JOB);
        u32 job = q->ring[q->head];
        q->head = (q->head + 1) % QCAP;
        q->count--;
        pthread_cond_signal(&q->has_space);
        pthread_mutex_unlock(&q->mtx);
        u32 x = 0; // the "work"
        for (u32 i = 0, n = (u32)(rnd() % 2048); i < n; i++) {
            x += i;
            __asm__ volatile("" : "+r"(x));
        }
        if (rnd() % 32 == 0) {
            nap(50 + rnd() % 200);
        }
        fence_signal(&qp->fence[job % NFENCE]);
        ADD(&sh->progress[CP_FUTEX], 1);
        seq_set(job);
    }
}

// Waits for the newest job while holding finish_lock (util_queue_finish's
// lock), contending with the submitter's own finish.
static void q_finisher(void) {
    struct qstate *q = &sh->q;
    for (;;) {
        simple_mtx_lock(&qp->finish_lock);
        u64 s = LOAD(&q->submitted);
        int waited = s ? fence_wait(&qp->fence[(s - 1) % NFENCE]) : 0;
        simple_mtx_unlock(&qp->finish_lock);
        seq_set(s);
        if (!waited) {
            nap(100 + rnd() % 400);
        }
    }
}

static void q_submitter(void) {
    struct qstate *q = &sh->q;
    for (u64 j = 0;; j++) {
        u32 *f = &qp->fence[j % NFENCE];
        fence_wait(f); // the slot's previous job must be done before reuse
        __atomic_store_n(f, 1, __ATOMIC_RELEASE); // util_queue_fence_reset
        q_lock();
        while (q->count == QCAP)
            q_cond_wait(&q->has_space, PH_COND_SPACE);
        q->ring[q->tail] = (u32)j;
        q->tail = (q->tail + 1) % QCAP;
        q->count++;
        STORE(&q->submitted, j + 1);
        pthread_cond_signal(&q->has_job);
        pthread_mutex_unlock(&q->mtx);
        seq_set(j);
        if (rnd() % 16 == 0) { // util_queue_finish
            simple_mtx_lock(&qp->finish_lock);
            for (int i = 0; i < NFENCE; i++)
                fence_wait(&qp->fence[i]);
            simple_mtx_unlock(&qp->finish_lock);
            ADD(&q->finishes, 1);
        }
        if (rnd() % 64 == 0) { // let the workers drain and park in cond_wait
            nap(rnd() % 300);
        }
    }
}

struct targ { int slot, role; };

static void *q_thread(void *p) {
    struct targ *a = p;
    slot_enter(a->slot);
    if (a->role == 0)
        q_worker();
    else
        q_finisher();
    return NULL;
}

static void start_thread(int comp, void *(*fn)(void *), void *arg) {
    pthread_t t;
    int e = pthread_create(&t, NULL, fn, arg);
    if (e)
        cfail(comp, "pthread_create: %s", strerror(e));
}

static void run_queue(int unused) {
    (void)unused;
    static struct targ args[NWORK + NFIN];
    struct qstate *q = &sh->q;
    if (pthread_mutex_init(&q->mtx, NULL) || pthread_cond_init(&q->has_job, NULL) ||
        pthread_cond_init(&q->has_space, NULL))
        cfail(CP_FUTEX, "pthread init failed");
    qp = mmap(NULL, sizeof *qp, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (qp == MAP_FAILED)
        cfail(CP_FUTEX, "mmap(qpriv): %s", strerror(errno));
    STORE(&q->priv_addr, (u64)(uintptr_t)qp);
    for (int i = 0; i < NWORK + NFIN; i++) {
        char nm[16];
        args[i].role = i >= NWORK;
        snprintf(nm, sizeof nm, i < NWORK ? "Q.work%d" : "Q.fin%d", i < NWORK ? i : i - NWORK);
        args[i].slot = slot_alloc(nm, CP_FUTEX);
        start_thread(CP_FUTEX, q_thread, &args[i]);
    }
    q_submitter();
}

// ── 4. child exit (P) ────────────────────────────────────────────────────

static volatile sig_atomic_t p_got;
static volatile pid_t p_want, p_other;
static volatile int p_status;

static void p_sigchld(int s) {
    (void)s;
    int e = errno;
    for (;;) {
        int st;
        pid_t r = waitpid(-1, &st, WNOHANG);
        if (r <= 0)
            break;
        if (r == p_want) {
            p_status = st;
            p_got = 1;
        } else {
            p_other = r;
        }
    }
    errno = e;
}

static void run_child_exit(int unused) {
    (void)unused;
    sigset_t chld, waitmask;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    CK(CP_CHILD, sigprocmask(SIG_BLOCK, &chld, &waitmask), "P sigprocmask");
    sigdelset(&waitmask, SIGCHLD);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = p_sigchld;
    sa.sa_flags = SA_NOCLDSTOP;
    sigemptyset(&sa.sa_mask);
    CK(CP_CHILD, sigaction(SIGCHLD, &sa, NULL), "P sigaction(SIGCHLD)");
    static uint8_t buf[8192];
    for (u64 i = 0;; i++) {
        int pfd[2], method = (int)(i % 3), want = (int)(i & 0x7f), st = 0;
        size_t len = 1 + (size_t)(rnd() % 8192), got = 0;
        CK(CP_CHILD, pipe(pfd), "P pipe");
        p_got = 0;
        pid_t pid = BLOCKING(PH_FORK, fork());
        if (pid < 0)
            cfail(CP_CHILD, "P fork: %s", strerror(errno));
        if (pid == 0) {
            close(pfd[0]);
            for (size_t j = 0; j < len; j++)
                buf[j] = (uint8_t)(i * 31 + j);
            for (size_t off = 0; off < len;) {
                ssize_t w = write(pfd[1], buf + off, len - off);
                if (w < 0) {
                    if (errno == EINTR)
                        continue;
                    _exit(200);
                }
                off += (size_t)w;
            }
            _exit(want);
        }
        p_want = pid; // the handler runs only inside sigsuspend
        STORE(&sh->p_pid, (int32_t)pid);
        STORE(&sh->p_method, method);
        seq_set(i);
        close(pfd[1]);
        for (;;) {
            struct pollfd p = {pfd[0], POLLIN, 0};
            int n = BLOCKING(PH_POLL, poll(&p, 1, -1));
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                cfail(CP_CHILD, "P poll(pipe): %s", strerror(errno));
            }
            if (p.revents & (POLLERR | POLLNVAL))
                cfail(CP_CHILD, "P poll(pipe) revents=0x%x", p.revents);
            ssize_t r = BLOCKING(PH_READ, read(pfd[0], buf, sizeof buf));
            if (r < 0) {
                if (errno == EINTR || errno == EAGAIN)
                    continue;
                cfail(CP_CHILD, "P read(pipe): %s", strerror(errno));
            }
            if (r == 0)
                break;
            for (ssize_t j = 0; j < r; j++)
                if (buf[j] != (uint8_t)(i * 31 + got + (size_t)j))
                    cfail(CP_CHILD, "P pipe byte %zu from child %d: expected 0x%02x got 0x%02x",
                          got + (size_t)j, pid, (uint8_t)(i * 31 + got + (size_t)j), buf[j]);
            got += (size_t)r;
            if (got > len)
                cfail(CP_CHILD, "P pipe from child %d: %zu bytes, child wrote %zu", pid, got, len);
        }
        close(pfd[0]);
        if (got != len)
            cfail(CP_CHILD, "P pipe from child %d: EOF after %zu of %zu bytes", pid, got, len);
        switch (method) {
        case 0:
            for (;;) {
                pid_t r = BLOCKING(PH_WAITPID, waitpid(pid, &st, 0));
                if (r == pid)
                    break;
                if (r < 0 && errno == EINTR)
                    continue;
                cfail(CP_CHILD, "P waitpid(%d) = %d: %s", pid, r, strerror(errno));
            }
            break;
        case 1:
            while (!p_got) {
                ph(PH_SIGSUSPEND);
                sigsuspend(&waitmask);
                ph(PH_RUN);
            }
            if (p_other)
                cfail(CP_CHILD, "P SIGCHLD handler reaped unexpected child %d", p_other);
            st = p_status;
            break;
        default: {
            siginfo_t si;
            for (;;) {
                memset(&si, 0, sizeof si);
                int r = BLOCKING(PH_WAITID, waitid(P_PID, (id_t)pid, &si, WEXITED));
                if (r == 0)
                    break;
                if (errno == EINTR)
                    continue;
                cfail(CP_CHILD, "P waitid(%d): %s", pid, strerror(errno));
            }
            if (si.si_pid != pid || si.si_code != CLD_EXITED)
                cfail(CP_CHILD, "P waitid(%d): si_pid=%d si_code=%d", pid, si.si_pid, si.si_code);
            st = (si.si_status & 0xff) << 8; // as a wait status
            break;
        }
        }
        if (!WIFEXITED(st) || WEXITSTATUS(st) != want)
            cfail(CP_CHILD, "P child %d (%s): status 0x%x, expected exit %d", pid,
                  reap_name[method], st, want);
        ADD(&sh->progress[CP_CHILD], 1);
    }
}

// ── 5. load ──────────────────────────────────────────────────────────────

static void run_toucher(int unused) {
    (void)unused;
    char cur[160], prev[160] = "";
    for (u64 n = 0;; n++) {
        snprintf(cur, sizeof cur, "%s/t%llu", g.fishdir, U(n));
        int fd = CK(CP_LOAD, open(cur, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600),
                    "toucher create");
        close(fd);
        if (prev[0])
            CK(CP_LOAD, unlink(prev), "toucher unlink");
        memcpy(prev, cur, sizeof cur);
        ADD(&sh->progress[CP_LOAD], 1);
        seq_set(n);
        nap(2000 + rnd() % 3000);
    }
}

static void *sleeper_thread(void *arg) {
    slot_enter((int)(intptr_t)arg);
    for (u64 n = 1;; n++) {
        nap(50 + rnd() % 951);
        seq_set(n);
    }
    return NULL;
}

// 4 nanosleep threads + this thread reading a 1 ms periodic timerfd.
static void run_sleepers(int unused) {
    (void)unused;
    for (int i = 0; i < 4; i++) {
        char nm[16];
        snprintf(nm, sizeof nm, "L.sleep%d", i);
        start_thread(CP_LOAD, sleeper_thread, (void *)(intptr_t)slot_alloc(nm, CP_LOAD));
    }
    int tfd = CK(CP_LOAD, timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC), "L timerfd_create");
    struct itimerspec its = {{0, 1000000}, {0, 1000000}};
    CK(CP_LOAD, timerfd_settime(tfd, 0, &its, NULL), "L timerfd_settime");
    for (u64 total = 0;;) {
        u64 v;
        ssize_t r = BLOCKING(PH_READ, read(tfd, &v, sizeof v));
        if (r < 0 && errno == EINTR)
            continue;
        if (r != sizeof v)
            cfail(CP_LOAD, "L read(timerfd): %s", r < 0 ? strerror(errno) : "short");
        total += v;
        seq_set(total);
    }
}

static void *mmap_thread(void *arg) {
    if (arg)
        slot_enter((int)(intptr_t)arg - 1);
    for (u64 n = 0;; n++) {
        uint8_t *p = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            cfail(CP_LOAD, "L mmap: %s", strerror(errno));
        for (size_t off = 0; off < 65536; off += 4096)
            p[off] = (uint8_t)n;
        if (munmap(p, 65536) < 0)
            cfail(CP_LOAD, "L munmap: %s", strerror(errno));
        seq_set(n);
        ph(PH_YIELD);
        sched_yield();
        ph(PH_RUN);
    }
    return NULL;
}

// Two threads of one mm on different CPUs: every munmap needs a shootdown.
static void run_mmapper(int unused) {
    (void)unused;
    start_thread(CP_LOAD, mmap_thread, (void *)(intptr_t)(slot_alloc("L.mmap1", CP_LOAD) + 1));
    mmap_thread(NULL);
}

static void run_hog(int unused) {
    (void)unused;
    for (u64 n = 0;; n++) {
        u64 t0 = now_us();
        while (now_us() - t0 < 1000)
            ;
        seq_set(n);
        nap(1000);
    }
}

// ── monitor ──────────────────────────────────────────────────────────────

static int track(int fd, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int track(int fd, const char *fmt, ...) {
    if (fd >= 0 && nfdl < MAXFDL) {
        va_list ap;
        va_start(ap, fmt);
        fdl[nfdl].fd = fd;
        vsnprintf(fdl[nfdl].label, sizeof fdl[nfdl].label, fmt, ap);
        va_end(ap);
        nfdl++;
    }
    return fd;
}

static pid_t spawn(const char *name, int comp, void (*fn)(int), int arg) {
    int s = slot_alloc(name, comp);
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0)
        cfail(CP_SETUP, "fork(%s): %s", name, strerror(errno));
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() != g.monitor)
            _exit(1);
        setpgid(0, g.pgid); // first child: its own group; the rest join it
        slot_enter(s);
        fn(arg);
        _exit(0);
    }
    if (!g.pgid)
        g.pgid = pid;
    setpgid(pid, g.pgid); // also from the parent, to close the race
    STORE(&sh->slot[s].pid, (int32_t)pid);
    STORE(&sh->slot[s].tid, (int32_t)pid);
    kids[nkids].pid = pid;
    kids[nkids].slot = s;
    kids[nkids].alive = 1;
    nkids++;
    return pid;
}

static void read_small(const char *path, char *out, size_t n) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(out, n, "(%s)", strerror(errno));
        return;
    }
    ssize_t r = read(fd, out, n - 1);
    int e = errno;
    close(fd);
    if (r < 0) {
        snprintf(out, n, "(%s)", strerror(e));
        return;
    }
    while (r > 0 && (out[r - 1] == '\n' || out[r - 1] == ' '))
        r--;
    out[r] = 0;
    for (ssize_t i = 0; i < r; i++)
        if (out[i] == '\n')
            out[i] = ';';
        else if (out[i] == '\t')
            out[i] = ' ';
}

static void fionread(int fd, char *out, size_t n) {
    int v = 0;
    if (ioctl(fd, FIONREAD, &v) == 0)
        snprintf(out, n, "%d", v);
    else
        snprintf(out, n, "err(%s)", strerror(errno));
}

static void app(char *out, size_t n, size_t *o, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void app(char *out, size_t n, size_t *o, const char *fmt, ...) {
    if (*o >= n)
        return;
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(out + *o, n - *o, fmt, ap);
    va_end(ap);
    if (w > 0)
        *o += (size_t)w;
}

static pid_t q_pid;

// Snapshot Q's private futex words: process_vm_readv, else /proc/<pid>/mem.
static int read_qpriv(struct qpriv *out, char *err, size_t n) {
    u64 addr = LOAD(&sh->q.priv_addr);
    if (!addr || q_pid <= 0) {
        snprintf(err, n, "not mapped yet");
        return -1;
    }
    struct iovec l = {out, sizeof *out}, r = {(void *)(uintptr_t)addr, sizeof *out};
    if (process_vm_readv(q_pid, &l, 1, &r, 1, 0) == (ssize_t)sizeof *out)
        return 0;
    int e = errno;
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/mem", q_pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t x = pread(fd, out, sizeof *out, (off_t)addr);
        close(fd);
        if (x == (ssize_t)sizeof *out)
            return 0;
    }
    snprintf(err, n, "unreadable: process_vm_readv: %s", strerror(e));
    return -1;
}

static void describe_futex(char *out, size_t n, size_t *o) {
    struct qstate *q = &sh->q;
    struct qpriv v;
    char err[96];
    const u32 *mw = (const u32 *)&q->mtx; // glibc: lock, count, owner, nusers
    app(out, n, o, "submitted=%llu completed=%llu finishes=%llu queued=%u mutex words=%u/%u/%u/%u; ",
        U(LOAD(&q->submitted)), U(LOAD(&sh->progress[CP_FUTEX])), U(LOAD(&q->finishes)),
        LOAD(&q->count), LOAD(&mw[0]), LOAD(&mw[1]), LOAD(&mw[2]), LOAD(&mw[3]));
    if (read_qpriv(&v, err, sizeof err) < 0) {
        app(out, n, o, "finish_lock/fences %s", err);
        return;
    }
    app(out, n, o, "finish_lock=%u unsignalled fences:", v.finish_lock);
    for (int i = 0; i < NFENCE; i++)
        if (v.fence[i])
            app(out, n, o, " [%d]=%u", i, v.fence[i]);
}

static void describe_stall(int c, u64 ms, char *out, size_t n) {
    size_t o = 0;
    char f1[32], f2[32];
    if (c <= CP_CHAIN2) {
        struct chain_dbg *d = &sh->ch[c];
        u64 sent = LOAD(&d->sent), ver = LOAD(&sh->progress[c]);
        app(out, n, &o, "relay stall: no byte verified for %llu ms (sent=%llu verified=%llu "
            "in_flight=%llu; F %s", U(ms), U(sent), U(ver), U(sent - ver),
            LOAD(&d->f_cmd_running) ? "waiting for its command" : "idle");
        if (LOAD(&d->f_cmd_running))
            app(out, n, &o, " pid %d", LOAD(&d->f_cmd_pid));
        app(out, n, &o, ") -- lost/late wakeup in the pty/unix-socket chain");
    } else if (c == CP_EPOLL) {
        u32 k = LOAD(&sh->stim_kind);
        fionread(g.r_ack[1], f1, sizeof f1);
        fionread(g.r_dg[0], f2, sizeof f2);
        app(out, n, &o, "epoll lost wakeup: stimulus %s seq=%llu outstanding %llu ms "
            "(acked=%llu; D's ack queue FIONREAD=%s, R's unix dgram FIONREAD=%s)",
            stim_name[k < NSTIM ? k : 0], U(LOAD(&sh->stim_seq)),
            U(now_ms() - LOAD(&sh->stim_t_ms)), U(LOAD(&sh->acked_seq)), f1, f2);
    } else if (c == CP_TIMER) {
        app(out, n, &o, "timerfd stall: no 7 ms expiration consumed by R for %llu ms "
            "(total=%llu) -- epoll_wait not woken by the timerfd", U(ms),
            U(LOAD(&sh->progress[CP_TIMER])));
    } else if (c == CP_FUTEX) {
        app(out, n, &o, "futex lost wakeup: no job completed for %llu ms (", U(ms));
        describe_futex(out, n, &o);
        app(out, n, &o, ")");
    } else if (c == CP_CHILD) {
        int m = LOAD(&sh->p_method);
        app(out, n, &o, "child exit not observed for %llu ms: child pid %d, reaping by %s "
            "(children reaped=%llu)", U(ms), LOAD(&sh->p_pid), reap_name[m >= 0 && m < 3 ? m : 0],
            U(LOAD(&sh->progress[CP_CHILD])));
    }
}

static void dump(void) {
    printf("--- readiness-stress state dump (seed=0x%llx ncpus=%d ipv6=%s pin_fail=%d "
           "fail_slot=%d) ---\n", U(g.seed), g.ncpus, g.ipv6 ? "yes" : "no", sh->pin_fail,
           sh->fail_slot);
    int ns = LOAD(&sh->nslots);
    if (ns > MAXSLOT)
        ns = MAXSLOT;
    for (int i = 0; i < ns; i++) {
        struct slot *s = &sh->slot[i];
        char path[96], stat[512], wchan[128], sysc[256];
        int p = LOAD(&s->phase), c = s->comp;
        snprintf(path, sizeof path, "/proc/%d/task/%d/stat", s->pid, s->tid);
        read_small(path, stat, sizeof stat);
        char *rp = strrchr(stat, ')');
        char state = rp && rp[1] == ' ' ? rp[2] : '?';
        snprintf(path, sizeof path, "/proc/%d/task/%d/wchan", s->pid, s->tid);
        read_small(path, wchan, sizeof wchan);
        snprintf(path, sizeof path, "/proc/%d/task/%d/syscall", s->pid, s->tid);
        read_small(path, sysc, sizeof sysc);
        printf("  [%2d] %-11s pid=%-6d tid=%-6d phase=%-24s seq=%-9llu progress(%s)=%llu "
               "state=%c wchan=%s syscall=%s\n", i, s->name, s->pid, s->tid,
               p >= 0 && p < PH_COUNT ? phase_name[p] : "?", U(LOAD(&s->seq)),
               c >= 0 && c < CP_COUNT ? comp_name[c] : "?",
               U(c >= 0 && c < CP_COUNT ? LOAD(&sh->progress[c]) : 0), state, wchan, sysc);
    }
    for (int i = 0; i < nfdl; i++) {
        char fion[64], rb[64], path[64], info[512];
        struct pollfd p = {fdl[i].fd, POLLIN | POLLOUT, 0};
        fionread(fdl[i].fd, fion, sizeof fion);
        if (poll(&p, 1, 0) < 0)
            snprintf(rb, sizeof rb, "err(%s)", strerror(errno));
        else
            revstr(p.revents, rb, sizeof rb);
        snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fdl[i].fd);
        read_small(path, info, sizeof info);
        printf("  fd %-3d %-20s FIONREAD=%-10s revents=%-16s fdinfo: %s\n", fdl[i].fd,
               fdl[i].label, fion, rb, info);
    }
    for (int k = 0; k < NCHAIN; k++) {
        struct chain_dbg *d = &sh->ch[k];
        printf("  chain%d: sent=%llu verified=%llu maxrtt_us=%llu late=%llu commands=%llu "
               "F.cmd_running=%d F.cmd_pid=%d F.inotify_events=%llu\n", k + 1,
               U(LOAD(&d->sent)), U(LOAD(&sh->progress[k])), U(LOAD(&d->maxrtt_us)),
               U(LOAD(&d->late)), U(LOAD(&d->cmds)), LOAD(&d->f_cmd_running),
               LOAD(&d->f_cmd_pid), U(LOAD(&d->f_inotify)));
    }
    u32 k = LOAD(&sh->stim_kind);
    printf("  epoll: stimulus=%s seq=%llu age_ms=%llu acked=%llu timer_expirations=%llu "
           "max_useless_wakes=%llu seen:", stim_name[k < NSTIM ? k : 0],
           U(LOAD(&sh->stim_seq)), U(now_ms() - LOAD(&sh->stim_t_ms)),
           U(LOAD(&sh->acked_seq)), U(LOAD(&sh->progress[CP_TIMER])),
           U(LOAD(&sh->r_useless_max)));
    for (int i = 0; i < NSTIM; i++)
        printf(" %s=%llu", stim_name[i], U(LOAD(&sh->r_seen[i])));
    char fq[1024];
    size_t o = 0;
    describe_futex(fq, sizeof fq, &o);
    printf("\n  futex: %s\n  futex: cond words has_job:", fq);
    const u32 *w = (const u32 *)&sh->q.has_job;
    for (size_t i = 0; i < sizeof sh->q.has_job / 4; i++)
        printf(" %u", w[i]);
    printf(" has_space:");
    w = (const u32 *)&sh->q.has_space;
    for (size_t i = 0; i < sizeof sh->q.has_space / 4; i++)
        printf(" %u", w[i]);
    int m = LOAD(&sh->p_method);
    printf("\n  child: reaped=%llu current pid=%d method=%s\n--- end dump ---\n",
           U(LOAD(&sh->progress[CP_CHILD])), LOAD(&sh->p_pid),
           reap_name[m >= 0 && m < 3 ? m : 0]);
    fflush(stdout);
}

static void reap_check(void) {
    for (;;) {
        int st;
        pid_t r = waitpid(-1, &st, WNOHANG);
        if (r <= 0)
            return;
        for (int i = 0; i < nkids; i++) {
            if (kids[i].pid != r)
                continue;
            kids[i].alive = 0;
            struct slot *s = &sh->slot[kids[i].slot];
            if (WIFSIGNALED(st))
                mfail(s->comp, "%s (pid %d) died unexpectedly: signal %d", s->name, r,
                      WTERMSIG(st));
            else
                mfail(s->comp, "%s (pid %d) exited unexpectedly: status %d", s->name, r,
                      WEXITSTATUS(st));
        }
        // anything else is a grandchild reparented to us (subreaper)
    }
}

static int finish_fail(void) {
    for (int i = 0; i < 100 && LOAD(&sh->fail) != 2; i++)
        sleep_us(2000);
    int c = sh->fail_comp;
    printf("readiness-stress FAIL %s: %s\n", c >= 0 && c < CP_COUNT ? comp_name[c] : "?",
           sh->reason);
    fflush(stdout);
    dump();
    STORE(&sh->stopping, 1);
    kill_all(SIGKILL);
    reap_all(3000);
    cleanup_dirs();
    return 1;
}

static int finish_ok(void) {
    kill_all(SIGTERM);
    reap_all(2000);
    kill_all(SIGKILL);
    reap_all(3000);
    cleanup_dirs();
    u64 bytes = 0, maxrtt = 0, late = 0;
    for (int k = 0; k < NCHAIN; k++) {
        bytes += LOAD(&sh->progress[k]);
        late += LOAD(&sh->ch[k].late);
        if (LOAD(&sh->ch[k].maxrtt_us) > maxrtt)
            maxrtt = LOAD(&sh->ch[k].maxrtt_us);
    }
    printf("readiness-stress-ok chains=%d bytes=%llu maxrtt_ms=%llu late=%llu epoll_events=%llu "
           "futex_jobs=%llu children=%llu ipv6=%s\n", NCHAIN, U(bytes), U((maxrtt + 999) / 1000),
           U(late), U(LOAD(&sh->progress[CP_EPOLL])), U(LOAD(&sh->progress[CP_FUTEX])),
           U(LOAD(&sh->progress[CP_CHILD])), g.ipv6 ? "yes" : "no");
    fflush(stdout);
    return 0;
}

static int run_monitor(int seconds) {
    u64 start = now_ms(), prev = start, lastv[CP_NMON], lastt[CP_NMON];
    char why[sizeof sh->reason];
    for (int c = 0; c < CP_NMON; c++) {
        lastv[c] = LOAD(&sh->progress[c]);
        lastt[c] = start;
    }
    for (;;) {
        sleep_us(TICK_MS * 1000);
        u64 t = now_ms();
        if (LOAD(&sh->fail))
            break;
        if (t - prev > STALL_MS) {
            mfail(CP_MONITOR, "monitor nanosleep(%d ms) returned after %llu ms (late timer "
                  "wakeup)", TICK_MS, U(t - prev));
            break;
        }
        prev = t;
        reap_check();
        for (int c = 0; c < CP_NMON && !LOAD(&sh->fail); c++) {
            u64 v = LOAD(&sh->progress[c]);
            if (v != lastv[c]) {
                lastv[c] = v;
                lastt[c] = t;
            } else if (t - lastt[c] >= STALL_MS) {
                describe_stall(c, t - lastt[c], why, sizeof why);
                mfail(c, "%s", why);
            }
        }
        if (LOAD(&sh->fail))
            break;
        if (t - start >= (u64)seconds * 1000) {
            STORE(&sh->stopping, 1);
            if (LOAD(&sh->fail)) // a failure that raced the stop still counts
                break;
            return finish_ok();
        }
    }
    return finish_fail();
}

static void on_alarm(int s) {
    (void)s;
    static const char m[] = "readiness-stress FAIL monitor: overall deadline exceeded\n";
    if (write(1, m, sizeof m - 1) < 0) {
    }
    kill_all(SIGKILL);
    _exit(1);
}

// ── setup ────────────────────────────────────────────────────────────────

static void setup_ipv6(void) {
    g.u6rx = g.u6tx = -1;
    g.ipv6 = 0;
    struct sockaddr_in6 a;
    socklen_t al = sizeof a;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    a.sin6_addr = in6addr_loopback;
    int rx = socket(AF_INET6, SOCK_DGRAM, 0);
    if (rx < 0)
        return;
    int tx = socket(AF_INET6, SOCK_DGRAM, 0);
    if (tx < 0 || bind(rx, (struct sockaddr *)&a, sizeof a) < 0 ||
        getsockname(rx, (struct sockaddr *)&a, &al) < 0 ||
        connect(tx, (struct sockaddr *)&a, sizeof a) < 0 || send(tx, "probe", 5, 0) != 5)
        goto unavailable;
    struct pollfd p = {rx, POLLIN, 0};
    int n = poll(&p, 1, 1000);
    char b[16];
    ssize_t r = recv(rx, b, sizeof b, MSG_DONTWAIT);
    if (r == 5 && n != 1)
        cfail(CP_SETUP, "udp6 probe: datagram queued on [::1] but poll(POLLIN, 1000 ms) = %d "
              "(lost wakeup)", n);
    if (r != 5)
        goto unavailable;
    g.u6rx = track(rx, "R udp6 [::1]");
    g.u6tx = track(tx, "D udp6");
    g.ipv6 = 1;
    return;
unavailable:
    close(rx);
    if (tx >= 0)
        close(tx);
}

int main(int argc, char **argv) {
    int seconds = argc > 1 ? atoi(argv[1]) : 240;
    if (seconds <= 0) {
        fprintf(stderr, "usage: %s [seconds [seed]]\n", argv[0]);
        return 2;
    }
    g.monitor = getpid();
    g.seed = argc > 2 ? strtoull(argv[2], NULL, 0) : 0x5eed0000ULL + (u64)getpid();
    sh = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sh == MAP_FAILED) {
        printf("readiness-stress FAIL setup: mmap(MAP_SHARED): %s\n", strerror(errno));
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1); // R reads it from a signalfd; blocked before R exists
    CK(CP_SETUP, sigprocmask(SIG_BLOCK, &usr1, NULL), "sigprocmask");

    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof set, &set) == 0)
        for (int c = 0; c < CPU_SETSIZE; c++)
            if (CPU_ISSET(c, &set))
                g.cpus[g.ncpus++] = c;

    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp || strlen(tmp) > 40)
        tmp = "/tmp";
    snprintf(g.base, sizeof g.base, "%s/rstress.%d", tmp, (int)getpid());
    snprintf(g.fishdir, sizeof g.fishdir, "%s/fish", g.base);
    snprintf(g.resdir, sizeof g.resdir, "%s/resolved", g.base);
    if (mkdir(g.base, 0700) < 0) {
        int e = errno;
        char b[sizeof g.base];
        memcpy(b, g.base, sizeof b);
        g.base[0] = 0; // not ours: never remove it
        cfail(CP_SETUP, "mkdir %s: %s", b, strerror(e));
    }
    CK(CP_SETUP, mkdir(g.fishdir, 0700), "mkdir fish dir");
    CK(CP_SETUP, mkdir(g.resdir, 0700), "mkdir resolved dir");

    for (int k = 0; k < NCHAIN; k++) {
        for (int b = 0; b < 2; b++) {
            char *name = b ? g.bname[k] : g.aname[k];
            int m = CK(CP_SETUP, posix_openpt(O_RDWR | O_NOCTTY), "posix_openpt");
            CK(CP_SETUP, grantpt(m), "grantpt");
            CK(CP_SETUP, unlockpt(m), "unlockpt");
            if (ptsname_r(m, name, sizeof g.aname[k]) != 0)
                cfail(CP_SETUP, "ptsname_r failed");
            int s = CK(CP_SETUP, open(name, O_RDWR | O_NOCTTY), "open pty slave");
            tty_raw(CP_SETUP, s, "pty slave raw"); // before anyone writes: no echo ever
            track(m, "chain%d %s_m", k + 1, b ? "B" : "A");
            track(s, "chain%d %s_s", k + 1, b ? "B" : "A");
            *(b ? &g.bm[k] : &g.am[k]) = m;
            *(b ? &g.bs[k] : &g.as[k]) = s;
        }
        CK(CP_SETUP, socketpair(AF_UNIX, SOCK_STREAM, 0, g.sk[k]), "socketpair(stream)");
        track(g.sk[k][0], "chain%d sock(C)", k + 1);
        track(g.sk[k][1], "chain%d sock(V)", k + 1);
        g.f_ino[k] = track(CK(CP_SETUP, inotify_init1(IN_NONBLOCK), "inotify_init1"),
                           "chain%d F.inotify", k + 1);
        CK(CP_SETUP, inotify_add_watch(g.f_ino[k], g.fishdir, IN_CREATE | IN_DELETE),
           "inotify_add_watch(fish)");
        g.f_efd[k] = track(CK(CP_SETUP, eventfd(0, EFD_NONBLOCK), "eventfd"),
                           "chain%d F.eventfd", k + 1);
    }
    CK(CP_SETUP, socketpair(AF_UNIX, SOCK_DGRAM, 0, g.r_dg), "socketpair(dgram)");
    track(g.r_dg[0], "R unix-dgram(R)");
    track(g.r_dg[1], "R unix-dgram(D)");
    CK(CP_SETUP, socketpair(AF_UNIX, SOCK_DGRAM, 0, g.r_ack), "socketpair(dgram)");
    track(g.r_ack[0], "R ack(R)");
    track(g.r_ack[1], "R ack(D)");
    g.r_tfd = track(CK(CP_SETUP, timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK), "timerfd"),
                    "R timerfd");
    g.r_efd = track(CK(CP_SETUP, eventfd(0, EFD_NONBLOCK), "eventfd"), "R eventfd");
    g.r_ino = track(CK(CP_SETUP, inotify_init1(IN_NONBLOCK), "inotify_init1"), "R inotify");
    CK(CP_SETUP, inotify_add_watch(g.r_ino, g.resdir, IN_CREATE), "inotify_add_watch(res)");
    g.r_ep = track(CK(CP_SETUP, epoll_create1(0), "epoll_create1"), "R epoll");
    setup_ipv6();

    // Best effort: lets the final reap collect grandchildren orphaned by the kill.
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0) {
    }
    signal(SIGALRM, on_alarm);
    alarm((unsigned)seconds + 30);

    static void (*const chain_fn[4])(int) = {run_terminal, run_client, run_server, run_fish};
    static const char *const chain_role[4] = {"T", "C", "V", "F"};
    for (int k = 0; k < NCHAIN; k++)
        for (int r = 0; r < 4; r++) {
            char nm[16];
            snprintf(nm, sizeof nm, "chain%d.%s", k + 1, chain_role[r]);
            spawn(nm, CP_CHAIN0 + k, chain_fn[r], k);
        }
    g.r_pid = spawn("R.resolved", CP_EPOLL, run_resolved, 0);
    spawn("D.driver", CP_EPOLL, run_driver, 0);
    q_pid = spawn("Q.submit", CP_FUTEX, run_queue, 0);
    spawn("P.bash", CP_CHILD, run_child_exit, 0);
    spawn("L.toucher", CP_LOAD, run_toucher, 0);
    spawn("L.timer", CP_LOAD, run_sleepers, 0);
    spawn("L.mmap0", CP_LOAD, run_mmapper, 0);
    spawn("L.hog0", CP_LOAD, run_hog, 0);
    spawn("L.hog1", CP_LOAD, run_hog, 0);
    return run_monitor(seconds);
}
