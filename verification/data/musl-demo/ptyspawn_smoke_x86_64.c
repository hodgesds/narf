// Replicate what a terminal emulator does to get a shell, and report the
// errno of every step.
//
// On the Fedora KDE image, kwin composites a decorated `foot` window that
// renders its grid and cursor block but shows NO PROMPT. foot itself works —
// it is a live Wayland client with correct decorations — so the failure is
// the shell it spawns, not rendering.
//
// foot (like every VTE/alacritty/xterm) does:
//   1. posix_openpt(O_RDWR|O_NOCTTY)      -> master fd on /dev/ptmx
//   2. grantpt() / unlockpt()             -> TIOCSPTLCK
//   3. ptsname()                          -> TIOCGPTN, "/dev/pts/N"
//   4. fork()
//   5. child: setsid(), open the slave, dup onto 0/1/2, exec the shell
//   6. parent: read() the master and paint what comes back
//
// A prompt appearing requires ALL of that. This walks the same sequence and
// prints each step's errno, so a failure names the syscall instead of
// leaving "the terminal is empty".
//
// Build PIE, not -static: NARF rejects non-PIE ELFs with execve EINVAL,
// which looks like the probe failing rather than never running.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

static int step(const char *what, int rc)
{
    if (rc < 0)
        printf("PTY: %-30s FAILED errno=%d (%s)\n", what, errno, strerror(errno));
    else
        printf("PTY: %-30s ok (%d)\n", what, rc);
    return rc;
}

int main(int argc, char **argv)
{
    // Child half: the terminal's shell. Writes to fd 1, which the parent
    // dup2'd onto the PTY slave, so the bytes must come back off the master.
    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        write(1, "PTY-CHILD-ALIVE\n", 16);
        _exit(0);
    }
    printf("PTY: probe start uid=%d\n", (int)getuid());

    int m = step("posix_openpt(O_RDWR|NOCTTY)", posix_openpt(O_RDWR | O_NOCTTY));
    if (m < 0)
        return 1;
    step("grantpt", grantpt(m));
    step("unlockpt (TIOCSPTLCK)", unlockpt(m));

    // ptsname needs TIOCGPTN. Without it there is no slave path to open and
    // the child has no controlling terminal — an empty window exactly.
    char *slave = ptsname(m);
    if (!slave) {
        printf("PTY: ptsname                       FAILED errno=%d (%s)\n",
               errno, strerror(errno));
        return 1;
    }
    printf("PTY: ptsname                       ok (%s)\n", slave);

    int s = step("open(slave)", open(slave, O_RDWR | O_NOCTTY));
    if (s < 0)
        return 1;

    pid_t pid = fork();
    if (pid < 0) {
        printf("PTY: fork                          FAILED errno=%d\n", errno);
        return 1;
    }
    if (pid == 0) {
        // Child: exactly what a terminal does before exec'ing the shell.
        setsid();
        ioctl(s, TIOCSCTTY, 0);
        dup2(s, 0);
        dup2(s, 1);
        dup2(s, 2);
        if (s > 2)
            close(s);
        close(m);
        // Echo a token the parent can look for, then exit. Using /bin/sh
        // rather than an interactive shell keeps the check deterministic:
        // we are testing the PTY path, not prompt rendering.
        // Exec OURSELVES, not /bin/sh. The smoke is staged at
        // /bin/ptyspawn_smoke in NARF's own initramfs and exists in the
        // distro image too, whereas /bin/sh exists only in the latter —
        // with /bin/sh this passed in the Fedora image and hung forever in
        // the native one, which measures the environment rather than the
        // PTY. Same convention as fork_exec_burst_smoke / popenw_smoke.
        // Still a real fork + setsid + dup2 + execve.
        execl("/bin/ptyspawn_smoke", "ptyspawn_smoke", "--child", (char *)NULL);
        _exit(127); // exec failed
    }

    close(s);
    // Parent: read the master, exactly as the terminal's event loop does.
    char buf[256];
    ssize_t n = read(m, buf, sizeof buf - 1);
    if (n > 0) {
        buf[n] = 0;
        for (char *p = buf; *p; p++)
            if (*p == '\r' || *p == '\n')
                *p = ' ';
        printf("PTY: master read                   ok (%zd) [%s]\n", n, buf);
    } else {
        printf("PTY: master read                   FAILED n=%zd errno=%d (%s) "
               "— the child's output never reached the terminal\n",
               n, errno, strerror(errno));
    }

    int st = 0;
    if (waitpid(pid, &st, 0) == pid)
        printf("PTY: child exit                    status=%d exited=%d code=%d\n",
               st, WIFEXITED(st), WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    else
        printf("PTY: waitpid                       FAILED errno=%d\n", errno);

    close(m);
    // A SINGLE unambiguous success marker on its own line.
    //
    // The run-interactive matcher requires its needle to be followed by
    // \r/\n, so a mid-line token silently never matches. And it must only
    // appear when EVERY step succeeded: gating the xtask smoke on
    // "probe done" (printed unconditionally) or on a substring of the
    // master-read line would pass while the child's output never arrived,
    // which is exactly the failure this probe exists to catch.
    int ok = n > 0 && strstr(buf, "PTY-CHILD-ALIVE") != NULL &&
             WIFEXITED(st) && WEXITSTATUS(st) == 0;
    printf("PTY: probe done\n");
    if (ok)
        printf("ptyspawn-ok\n");
    return ok ? 0 : 1;
}
