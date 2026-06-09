#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

static void w(const char *msg) {
    write(1, msg, strlen(msg));
}

#define FILE_PATH "/dev/shm/narf_fs_smoke.txt"
#define FILE_PATH_NEW "/dev/shm/narf_fs_smoke_new.txt"

int main() {
    int fd = open(FILE_PATH, O_CREAT | O_RDWR, 0644);
    if (fd < 0) { w("fs-fail: open\n"); return 1; }

    if (write(fd, "hello", 5) != 5) { w("fs-fail: write\n"); return 1; }
    
    if (lseek(fd, 0, SEEK_SET) != 0) { w("fs-fail: lseek\n"); return 1; }
    
    char buf[16] = {0};
    if (read(fd, buf, 5) != 5) { w("fs-fail: read\n"); return 1; }
    
    if (strcmp(buf, "hello") != 0) { w("fs-fail: bad read data\n"); return 1; }

    if (pread(fd, buf, 5, 0) != 5) { w("fs-fail: pread\n"); return 1; }
    
    struct stat st;
    if (fstat(fd, &st) != 0) { w("fs-fail: fstat\n"); return 1; }
    if (st.st_size != 5) { w("fs-fail: bad fstat size\n"); return 1; }
    
    close(fd);

    if (access(FILE_PATH, R_OK) != 0) { w("fs-fail: access\n"); return 1; }
    
    if (rename(FILE_PATH, FILE_PATH_NEW) != 0) {
        char fail_msg[64];
        snprintf(fail_msg, sizeof(fail_msg), "fs-fail: rename errno=%d\n", errno);
        w(fail_msg);
        return 1;
    }
    
    if (unlink(FILE_PATH_NEW) != 0) { w("fs-fail: unlink\n"); return 1; }

    w("fs-ok\n");
    return 0;
}
