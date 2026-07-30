/*
 * Live sched_{get,set}affinity(2) SMP regression.
 *
 * The scheduler's CpuSet is a hard dispatch constraint, but the original
 * Linux-compat handlers merely validated the user pointer, discarded every
 * set request, and always reported CPU 0.  That made existing "pinned" SMP
 * smokes run without any actual pinning.
 *
 * Exercise both self and remote-process affinity.  A self update must be
 * visible immediately and must move the task at the next cooperative yield.
 * A child in a separate mount namespace is affinity-updated by its outer PID
 * while parked; after release it must observe both the mask and the requested
 * CPU.  Empty and wholly-offline masks must be rejected.
 *
 * Success token: sched-affinity-smp-ok.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void fail(const char *why) {
    (void)!write(STDOUT_FILENO, why, strlen(why));
}

static void alarm_handler(int sig) {
    (void)sig;
    fail("sched-affinity-smp-fail: timeout\n");
    _exit(1);
}

static int current_cpu(void) {
    unsigned cpu = (unsigned)-1;
    if (syscall(SYS_getcpu, &cpu, NULL, NULL) != 0)
        return -1;
    return (int)cpu;
}

static int wait_for_cpu(int wanted) {
    for (int attempt = 0; attempt < 4096; attempt++) {
        if (current_cpu() == wanted)
            return 0;
        if (sched_yield() != 0)
            return -1;
    }
    return -1;
}

static int mask_is_cpu(const cpu_set_t *set, int cpu) {
    return CPU_COUNT(set) == 1 && CPU_ISSET(cpu, set);
}

int main(void) {
    signal(SIGALRM, alarm_handler);
    alarm(20);

    cpu_set_t original;
    CPU_ZERO(&original);
    if (sched_getaffinity(0, sizeof(original), &original) != 0 ||
        !CPU_ISSET(0, &original) || !CPU_ISSET(1, &original)) {
        fail("sched-affinity-smp-fail: initial online mask\n");
        return 1;
    }

    cpu_set_t cpu1;
    CPU_ZERO(&cpu1);
    CPU_SET(1, &cpu1);
    if (sched_setaffinity(0, sizeof(cpu1), &cpu1) != 0) {
        fail("sched-affinity-smp-fail: set self CPU 1\n");
        return 1;
    }
    cpu_set_t observed;
    CPU_ZERO(&observed);
    if (sched_getaffinity(0, sizeof(observed), &observed) != 0 ||
        !mask_is_cpu(&observed, 1)) {
        fail("sched-affinity-smp-fail: self mask round trip\n");
        return 1;
    }
    if (wait_for_cpu(1) != 0) {
        fail("sched-affinity-smp-fail: self migration\n");
        return 1;
    }

    cpu_set_t empty;
    CPU_ZERO(&empty);
    errno = 0;
    if (sched_setaffinity(0, sizeof(empty), &empty) == 0) {
        fail("sched-affinity-smp-fail: accepted empty mask\n");
        return 1;
    }

    cpu_set_t offline;
    CPU_ZERO(&offline);
    CPU_SET(CPU_SETSIZE - 1, &offline);
    errno = 0;
    if (sched_setaffinity(0, sizeof(offline), &offline) == 0) {
        fail("sched-affinity-smp-fail: accepted offline mask\n");
        return 1;
    }

    int ready[2];
    int release[2];
    if (pipe(ready) != 0 || pipe(release) != 0) {
        fail("sched-affinity-smp-fail: pipe\n");
        return 1;
    }
    pid_t child = fork();
    if (child < 0) {
        fail("sched-affinity-smp-fail: fork\n");
        return 1;
    }
    if (child == 0) {
        char byte;
        close(ready[0]);
        close(release[1]);
        if (unshare(CLONE_NEWNS) != 0 ||
            write(ready[1], "R", 1) != 1 ||
            read(release[0], &byte, 1) != 1) {
            _exit(2);
        }
        CPU_ZERO(&observed);
        if (sched_getaffinity(0, sizeof(observed), &observed) != 0 ||
            !mask_is_cpu(&observed, 0)) {
            _exit(3);
        }
        if (wait_for_cpu(0) != 0)
            _exit(4);
        _exit(0);
    }

    close(ready[1]);
    close(release[0]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) {
        fail("sched-affinity-smp-fail: child ready\n");
        return 1;
    }
    cpu_set_t cpu0;
    CPU_ZERO(&cpu0);
    CPU_SET(0, &cpu0);
    if (sched_setaffinity(child, sizeof(cpu0), &cpu0) != 0 ||
        write(release[1], "G", 1) != 1) {
        fail("sched-affinity-smp-fail: set child CPU 0\n");
        return 1;
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fail("sched-affinity-smp-fail: child result\n");
        return 1;
    }

    if (sched_setaffinity(0, sizeof(original), &original) != 0) {
        fail("sched-affinity-smp-fail: restore mask\n");
        return 1;
    }

    alarm(0);
    fail("sched-affinity-smp-ok\n");
    return 0;
}
