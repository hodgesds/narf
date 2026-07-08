#define _GNU_SOURCE 1
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

extern char **environ;

int main(void) {
    if (chroot("/mnt") != 0) { printf("dkde-chroot-fail errno=%d\n", errno); return 1; }
    if (chdir("/") != 0) { printf("dkde-chdir-fail errno=%d\n", errno); return 1; }
    
    // The wrapper script /bin/start_kde.sh sets XDG_RUNTIME_DIR and launches plasma
    setenv("PATH", "/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin", 1);
    setenv("WAYLAND_DISPLAY", "wayland-1", 1); 
    
    char *argv[] = { (char *)"/bin/start_kde.sh", NULL };
    execve("/bin/start_kde.sh", argv, environ);
    
    printf("dkde-exec-fail errno=%d\n", errno);
    return 1;
}
