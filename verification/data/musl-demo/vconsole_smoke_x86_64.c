// systemd-vconsole-setup's source-VT selection plus the ioctls `loadkeys`
// issues, against /dev/tty1.
//
// vconsole-setup (src/vconsole/vconsole-setup.c) checks VT N with
// access("/dev/vcsN"), then KDGKBMODE must be K_XLATE/K_UNICODE, then
// KDFONTOP(GET) tells it whether the console has fonts (ENOSYS = "no font
// support, skipping"); `loadkeys -C /dev/tty1 -u us` needs KDGKBTYPE ==
// KB_101, KDSKBENT, KDSKBSENT and KDSKBDIACRUC. On NARF /dev/vcs1 did not
// exist, so vconsole-setup failed "No virtual console that can be
// configured found: No such file or directory".
//
// Needs root (CAP_SYS_TTY_CONFIG) and a VT. Success token "vconsole-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

// include/uapi/linux/kd.h + keyboard.h (musl-gcc ships no kernel headers).
#define KDGKBTYPE 0x4B33
#define KB_101 0x02
#define KDGKBMODE 0x4B44
#define KDSKBMODE 0x4B45
#define K_XLATE 0x01
#define K_UNICODE 0x03
#define KDGKBENT 0x4B46
#define KDSKBENT 0x4B47
#define KDGKBSENT 0x4B48
#define KDSKBSENT 0x4B49
#define KDGKBDIACRUC 0x4BFA
#define KDSKBDIACRUC 0x4BFB
#define KDFONTOP 0x4B72
#define KD_FONT_OP_GET 1
#define K(t, v) (((t) << 8) | (v))
#define KT_CUR 6
#define KT_LETTER 11
struct kbentry {
    unsigned char kb_table, kb_index;
    unsigned short kb_value;
};
struct kbsentry {
    unsigned char kb_func;
    unsigned char kb_string[512];
};
struct kbdiacruc {
    unsigned int diacr, base, result;
};
struct kbdiacrsuc {
    unsigned int kb_cnt;
    struct kbdiacruc kbdiacruc[256];
};
struct console_font_op {
    unsigned int op, flags, width, height, charcount;
    unsigned char *data;
};

static int failures;

static void bad(const char *what, int err) {
    printf("vconsole-fail: %s (errno %d %s)\n", what, err, strerror(err));
    failures++;
}

int main(void) {
    if (access("/dev/vcs1", F_OK) != 0)
        bad("access(/dev/vcs1): VT 1 must look allocated", errno);
    int fd = open("/dev/tty1", O_RDWR | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        bad("open /dev/tty1", errno);
        return 1;
    }
    int mode = -1;
    if (ioctl(fd, KDGKBMODE, &mode) != 0)
        bad("KDGKBMODE", errno);
    else if (mode != K_XLATE && mode != K_UNICODE)
        printf("vconsole-fail: KDGKBMODE %d is not K_XLATE/K_UNICODE\n", mode), failures++;
    int saved = mode;
    if (ioctl(fd, KDSKBMODE, K_UNICODE) != 0)
        bad("KDSKBMODE K_UNICODE", errno);

    struct console_font_op cfo = {
        .op = KD_FONT_OP_GET, .width = ~0u, .height = ~0u, .charcount = ~0u};
    if (ioctl(fd, KDFONTOP, &cfo) == 0) {
        // A console with fonts is fine too (a real Linux VT).
    } else if (errno != ENOSYS && errno != EOPNOTSUPP && errno != ENOTTY) {
        bad("KDFONTOP GET must succeed or be not-supported", errno);
    }

    char kbtype = 0;
    if (ioctl(fd, KDGKBTYPE, &kbtype) != 0 || kbtype != KB_101)
        bad("KDGKBTYPE must be KB_101", errno);

    struct kbentry ke = {.kb_table = 0, .kb_index = 30};
    if (ioctl(fd, KDGKBENT, &ke) != 0)
        bad("KDGKBENT", errno);
    unsigned short old = ke.kb_value;
    ke.kb_value = K(KT_LETTER, 'a');
    if (ioctl(fd, KDSKBENT, &ke) != 0)
        bad("KDSKBENT K(KT_LETTER,'a')", errno);
    struct kbentry back = {.kb_table = 0, .kb_index = 30};
    if (ioctl(fd, KDGKBENT, &back) != 0 || back.kb_value != K(KT_LETTER, 'a'))
        bad("KDGKBENT read-back", errno);
    struct kbentry badent = {.kb_table = 0, .kb_index = 31, .kb_value = K(KT_CUR, 9)};
    if (ioctl(fd, KDSKBENT, &badent) == 0 || errno != EINVAL)
        bad("KDSKBENT K(KT_CUR,9) must be EINVAL", errno);
    ke.kb_value = old;
    ioctl(fd, KDSKBENT, &ke);

    struct kbsentry ks = {.kb_func = 20};
    if (ioctl(fd, KDGKBSENT, &ks) != 0)
        bad("KDGKBSENT", errno);
    char oldfunc[sizeof ks.kb_string];
    memcpy(oldfunc, ks.kb_string, sizeof oldfunc);
    strcpy((char *)ks.kb_string, "\033[34~");
    if (ioctl(fd, KDSKBSENT, &ks) != 0)
        bad("KDSKBSENT", errno);
    memcpy(ks.kb_string, oldfunc, sizeof oldfunc);
    ioctl(fd, KDSKBSENT, &ks);

    static struct kbdiacrsuc dia;
    if (ioctl(fd, KDGKBDIACRUC, &dia) != 0)
        bad("KDGKBDIACRUC", errno);
    else if (ioctl(fd, KDSKBDIACRUC, &dia) != 0)
        bad("KDSKBDIACRUC (write the table back)", errno);
    dia.kb_cnt = 256;
    if (ioctl(fd, KDSKBDIACRUC, &dia) == 0 || errno != EINVAL)
        bad("KDSKBDIACRUC with 256 entries must be EINVAL", errno);

    if (ioctl(fd, KDSKBMODE, 42) == 0 || errno != EINVAL)
        bad("KDSKBMODE 42 must be EINVAL", errno);
    if (saved == K_XLATE || saved == K_UNICODE)
        ioctl(fd, KDSKBMODE, saved);
    close(fd);
    if (failures)
        return 1;
    printf("vconsole-ok\n");
    return 0;
}
