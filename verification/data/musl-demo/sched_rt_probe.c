/* Live FIFO/RR regression probe. Build: musl-gcc -O2 -static -pthread.
 * Run as a privileged user in a disposable guest, on Linux or NARF.
 * Every test pins to one allowed CPU; an alarm bounds a broken scheduler. */
#define _GNU_SOURCE
#include <errno.h>
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct shared {
    int gate, ready, count;
    int events[32];
    uint64_t stamp[32];
};
static struct shared *s;
static uint64_t ns(clockid_t clock) {
    struct timespec t;
    if (clock_gettime(clock, &t)) { perror("clock_gettime"); _exit(2); }
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}
static void policy(int kind, int priority) {
    struct sched_param p = {.sched_priority = priority};
    if (syscall(SYS_sched_setscheduler, 0, kind, &p)) { perror("sched_setscheduler"); _exit(2); }
}
static void wake(int *p) { syscall(SYS_futex, p, FUTEX_WAKE, 32, 0, 0, 0); }
static void wait_value(int *p, int value) {
    while (__atomic_load_n(p, __ATOMIC_SEQ_CST) == value)
        syscall(SYS_futex, p, FUTEX_WAIT, value, 0, 0, 0);
}
static void event(int value) {
    int i = __atomic_fetch_add(&s->count, 1, __ATOMIC_SEQ_CST);
    if (i >= 32) _exit(3);
    s->events[i] = value;
    s->stamp[i] = ns(CLOCK_MONOTONIC);
}
static void busy(unsigned milliseconds) {
    uint64_t end = ns(CLOCK_THREAD_CPUTIME_ID) + milliseconds * 1000000ull;
    while (ns(CLOCK_THREAD_CPUTIME_ID) < end) __asm__ volatile("" ::: "memory");
}
static pid_t worker(int id, int kind) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(2); }
    if (!pid) {
        policy(kind, 60);
        __atomic_fetch_add(&s->ready, 1, __ATOMIC_SEQ_CST);
        wake(&s->ready);
        wait_value(&s->gate, 0);
        event(id);
        busy(kind == SCHED_FIFO ? 70 : 230);
        event(id + 10);
        _exit(0);
    }
    while (__atomic_load_n(&s->ready, __ATOMIC_SEQ_CST) < id)
        wait_value(&s->ready, id - 1);
    return pid;
}
static void reap(pid_t pid) {
    int status;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) {
        fprintf(stderr, "child failed: pid=%d status=%x\n", pid, status); exit(3);
    }
}
static void pair(int kind) {
    *s = (struct shared){0};
    policy(SCHED_FIFO, 90);
    pid_t a = worker(1, kind), b = worker(2, kind);
    __atomic_store_n(&s->gate, 1, __ATOMIC_SEQ_CST);
    wake(&s->gate);
    reap(a); reap(b);
    policy(SCHED_OTHER, 0);
    int fifo = s->events[1] == s->events[0] + 10;
    if (s->count != 4 || fifo != (kind == SCHED_FIFO)) {
        fprintf(stderr, "bad %s order: %d %d %d %d\n", kind == SCHED_FIFO ? "FIFO" : "RR",
                s->events[0], s->events[1], s->events[2], s->events[3]); exit(4);
    }
    printf("RT-PASS %s order=%d,%d,%d,%d\n", kind == SCHED_FIFO ? "FIFO" : "RR",
           s->events[0], s->events[1], s->events[2], s->events[3]);
}
static void timer_preemption(void) {
    *s = (struct shared){0};
    policy(SCHED_FIFO, 90);
    pid_t high = fork();
    if (high < 0) exit(2);
    if (!high) {
        policy(SCHED_FIFO, 70);
        struct timespec t = {.tv_nsec = 30000000};
        nanosleep(&t, 0);
        event(7);
        _exit(0);
    }
    policy(SCHED_FIFO, 60);
    event(6);
    busy(160);
    event(16);
    reap(high);
    policy(SCHED_OTHER, 0);
    if (s->count != 3 || s->events[0] != 6 || s->events[1] != 7 || s->events[2] != 16) {
        fprintf(stderr, "timer failed to preempt FIFO: %d,%d,%d\n", s->events[0], s->events[1], s->events[2]); exit(5);
    }
    printf("RT-PASS timer-preemption latency_us=%llu\n", (unsigned long long)((s->stamp[1]-s->stamp[0])/1000));
}
static void watchdog(void) {
    policy(SCHED_OTHER, 0);
    pid_t child = fork();
    if (child < 0) exit(2);
    if (!child) {
        struct rlimit r = {.rlim_cur = 20000, .rlim_max = 40000};
        if (setrlimit(RLIMIT_RTTIME, &r)) _exit(2);
        signal(SIGXCPU, SIG_IGN);
        policy(SCHED_FIFO, 60);
        for (;;) { busy(2); sched_yield(); }
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
        fprintf(stderr, "RT watchdog did not SIGKILL yielding thread: %x\n", status); exit(6);
    }
    puts("RT-PASS rlimit-rttime-yield");
}
static void inheritance_and_permissions(void) {
    policy(SCHED_FIFO | 0x40000000, 70); /* SCHED_RESET_ON_FORK */
    pid_t child = fork();
    if (child < 0) exit(2);
    if (!child) {
        if (syscall(SYS_sched_getscheduler, 0) != SCHED_OTHER) _exit(7);
        _exit(0);
    }
    reap(child);
    policy(SCHED_OTHER, 0);
    child = fork();
    if (child < 0) exit(2);
    if (!child) {
        struct rlimit limit = {.rlim_cur=40, .rlim_max=40};
        if (setrlimit(RLIMIT_RTPRIO, &limit) || syscall(SYS_setuid, 1000)) _exit(7);
        struct sched_param p = {.sched_priority=41};
        if (syscall(SYS_sched_setscheduler, 0, SCHED_FIFO, &p) != -1 || errno != EPERM) _exit(7);
        if (syscall(SYS_sched_getscheduler, 0) != SCHED_OTHER) _exit(7);
        policy(SCHED_FIFO, 40);
        p.sched_priority=41;
        if (syscall(SYS_sched_setscheduler, 0, SCHED_FIFO, &p) != -1 || errno != EPERM) _exit(7);
        if (syscall(SYS_sched_getparam, 0, &p) || p.sched_priority != 40) _exit(7);
        policy(SCHED_OTHER, 0);
        _exit(0);
    }
    reap(child);
    puts("RT-PASS reset-on-fork-and-rtprio-permissions");
}
int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    alarm(15);
    cpu_set_t allowed, pin;
    if (sched_getaffinity(0, sizeof allowed, &allowed)) return 2;
    CPU_ZERO(&pin);
    for (int cpu=0; cpu<CPU_SETSIZE; cpu++) if (CPU_ISSET(cpu, &allowed)) { CPU_SET(cpu, &pin); break; }
    if (sched_setaffinity(0, sizeof pin, &pin)) { perror("affinity"); return 2; }
    s = mmap(0, sizeof *s, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (s == MAP_FAILED) return 2;
    pair(SCHED_FIFO);
    pair(SCHED_RR);
    timer_preemption();
    watchdog();
    inheritance_and_permissions();
    puts("RT-SCHED-OK");
    return 0;
}
