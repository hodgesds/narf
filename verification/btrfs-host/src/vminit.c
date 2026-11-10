/*
 * PID 1 of the Linux guest `linuxvm.rs` boots to put a real kernel's btrfs
 * on a test image: mount /dev/vda (which replays a tree log), optionally run
 * the op script on /dev/vdb, then either list the tree and power off, or
 * announce a crash point and hang for the host to kill the VM.
 *
 * Built static by the harness (`cc -static`), no libc beyond syscalls and
 * stdio. Output protocol, one record per line on the serial console:
 *
 *   VM-UP <uname release>
 *   VM-MOUNT ok|fail <errno>
 *   VM-OP <line no> ok|fail <errno> <op text>
 *   VM-ENT <type> <mode octal> <nlink> <size> <fnv64 hex> <escaped path>
 *   VM-KMSG <kernel line mentioning BTRFS>
 *   VM-CRASH            (script asked for a crash here; nothing follows)
 *   VM-DONE ok|fail
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/xattr.h>
#include <unistd.h>

#define MNT "/mnt"

static void out(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static FILE *con;

#include <stdarg.h>
static void out(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(con, fmt, ap);
	va_end(ap);
	fputc('\n', con);
	fflush(con);
}

static void power_off(void)
{
	sync();
	reboot(RB_POWER_OFF);
	for (;;)
		pause();
}

/* The byte the host and the guest both write at absolute file offset `off`
 * for a write of `seed` (`linuxvm::pattern`). */
static unsigned char pattern(uint64_t seed, uint64_t off)
{
	uint64_t x = off * 0x9E3779B97F4A7C15ull ^ seed * 0xD6E8FEB86659FD93ull;
	x ^= x >> 29;
	x *= 0xBF58476D1CE4E5B9ull;
	return (unsigned char)(x >> 32);
}

static uint64_t fnv(uint64_t h, const unsigned char *p, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		h ^= p[i];
		h *= 0x100000001b3ull;
	}
	return h;
}

static void escape(const char *s, char *dst)
{
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (c <= 0x20 || c >= 0x7f || c == '\\')
			dst += sprintf(dst, "\\x%02x", c);
		else
			*dst++ = (char)c;
	}
	*dst = 0;
}

static int list_ok = 1;

static void list_dir(const char *path)
{
	struct dirent **names;
	int n = scandir(path, &names, NULL, alphasort);
	if (n < 0) {
		out("VM-ERR scandir %s: %d", path, errno);
		list_ok = 0;
		return;
	}
	for (int i = 0; i < n; i++) {
		const char *name = names[i]->d_name;
		char child[4096], esc[4 * 4096];
		struct stat st;
		uint64_t h = 0xcbf29ce484222325ull;
		char type = 'o';

		if (!strcmp(name, ".") || !strcmp(name, ".."))
			continue;
		snprintf(child, sizeof(child), "%s/%s", path, name);
		if (lstat(child, &st)) {
			out("VM-ERR lstat %s: %d", child, errno);
			list_ok = 0;
			continue;
		}
		if (S_ISREG(st.st_mode)) {
			static unsigned char buf[1 << 16];
			int fd = open(child, O_RDONLY);
			ssize_t r;
			type = 'f';
			if (fd < 0) {
				out("VM-ERR open %s: %d", child, errno);
				list_ok = 0;
				continue;
			}
			while ((r = read(fd, buf, sizeof(buf))) > 0)
				h = fnv(h, buf, (size_t)r);
			if (r < 0) {
				out("VM-ERR read %s: %d", child, errno);
				list_ok = 0;
			}
			close(fd);
		} else if (S_ISLNK(st.st_mode)) {
			char target[4096];
			ssize_t r = readlink(child, target, sizeof(target));
			type = 'l';
			if (r > 0)
				h = fnv(h, (unsigned char *)target, (size_t)r);
		} else if (S_ISDIR(st.st_mode)) {
			type = 'd';
		}
		escape(child + strlen(MNT) + 1, esc);
		out("VM-ENT %c %o %lu %llu %016llx %s", type,
		    (unsigned)(st.st_mode & 07777), (unsigned long)st.st_nlink,
		    S_ISDIR(st.st_mode) ? 0ull : (unsigned long long)st.st_size,
		    (unsigned long long)h, esc);
		if (type == 'd')
			list_dir(child);
		free(names[i]);
	}
	free(names);
}

static void kmsg(void)
{
	int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	char line[4096];
	ssize_t r;
	if (fd < 0)
		return;
	while ((r = read(fd, line, sizeof(line) - 1)) > 0) {
		char *msg;
		line[r] = 0;
		msg = strchr(line, ';');
		if (!msg || !(strstr(msg, "BTRFS") || strstr(msg, "btrfs")))
			continue;
		if (msg[strlen(msg) - 1] == '\n')
			msg[strlen(msg) - 1] = 0;
		out("VM-KMSG %s", msg + 1);
	}
	close(fd);
}

static char *full(const char *rel, char *buf)
{
	snprintf(buf, 4096, MNT "/%s", rel);
	return buf;
}

static int sync_path(const char *path, int flags, int data_only)
{
	int fd = open(path, flags);
	int r;
	if (fd < 0)
		return -1;
	r = data_only ? fdatasync(fd) : fsync(fd);
	close(fd);
	return r;
}

/* One script line. Returns 0 on success, -1 with errno set on failure,
 * 1 for `crash`. */
static int run_op(char *line)
{
	char a[4096], b[4096], pa[4096], pb[4096];
	unsigned long long x, y, z;

	if (sscanf(line, "mkdir %4095s", a) == 1)
		return mkdir(full(a, pa), 0755);
	if (sscanf(line, "write %4095s %llu %llu %llu", a, &x, &y, &z) == 4) {
		int fd = open(full(a, pa), O_WRONLY | O_CREAT, 0644);
		unsigned char *buf;
		ssize_t r;
		if (fd < 0)
			return -1;
		buf = malloc(y ? y : 1);
		for (unsigned long long i = 0; i < y; i++)
			buf[i] = pattern(z, x + i);
		r = pwrite(fd, buf, y, (off_t)x);
		free(buf);
		close(fd);
		return r == (ssize_t)y ? 0 : -1;
	}
	if (sscanf(line, "truncate %4095s %llu", a, &x) == 2)
		return truncate(full(a, pa), (off_t)x);
	if (sscanf(line, "falloc %4095s %llu %llu %llu", a, &x, &y, &z) == 4) {
		int fd = open(full(a, pa), O_WRONLY | O_CREAT, 0644);
		int r;
		if (fd < 0)
			return -1;
		r = fallocate(fd, (int)x, (off_t)y, (off_t)z);
		close(fd);
		return r;
	}
	if (sscanf(line, "fsyncdir %4095s", a) == 1)
		return sync_path(full(strcmp(a, ".") ? a : "", pa),
				 O_RDONLY | O_DIRECTORY, 0);
	if (sscanf(line, "fsync %4095s", a) == 1)
		return sync_path(full(a, pa), O_RDONLY, 0);
	if (sscanf(line, "fdatasync %4095s", a) == 1)
		return sync_path(full(a, pa), O_RDONLY, 1);
	if (sscanf(line, "rename %4095s %4095s", a, b) == 2)
		return rename(full(a, pa), full(b, pb));
	if (sscanf(line, "link %4095s %4095s", a, b) == 2)
		return link(full(a, pa), full(b, pb));
	if (sscanf(line, "symlink %4095s %4095s", a, b) == 2)
		return symlink(a, full(b, pb));
	if (sscanf(line, "unlink %4095s", a) == 1)
		return unlink(full(a, pa));
	if (sscanf(line, "rmdir %4095s", a) == 1)
		return rmdir(full(a, pa));
	if (sscanf(line, "chmod %4095s %llo", a, &x) == 2)
		return chmod(full(a, pa), (mode_t)x);
	if (sscanf(line, "setxattr %4095s %4095s %llu %llu", a, b, &x, &y) == 4) {
		unsigned char val[4096];
		if (x > sizeof(val))
			x = sizeof(val);
		for (unsigned long long i = 0; i < x; i++)
			val[i] = pattern(y, i);
		return setxattr(full(a, pa), b, val, x, 0);
	}
	if (sscanf(line, "rmxattr %4095s %4095s", a, b) == 2)
		return removexattr(full(a, pa), b);
	if (!strncmp(line, "sync", 4)) {
		int fd = open(MNT, O_RDONLY | O_DIRECTORY);
		int r;
		if (fd < 0)
			return -1;
		r = syncfs(fd);
		close(fd);
		return r;
	}
	if (!strncmp(line, "crash", 5))
		return 1;
	errno = ENOSYS;
	return -1;
}

static int run_script(void)
{
	int fd = open("/dev/vdb", O_RDONLY);
	static char script[1 << 20];
	ssize_t n;
	char *save = NULL;
	int lineno = 0, ok = 1;

	if (fd < 0)
		return 1; /* no script disk: verify only */
	n = read(fd, script, sizeof(script) - 1);
	close(fd);
	if (n < 0)
		return 0;
	script[n] = 0;
	for (char *line = strtok_r(script, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		int r;
		lineno++;
		if (!*line || *line == '#')
			continue;
		errno = 0;
		r = run_op(line);
		if (r == 1) {
			out("VM-CRASH");
			for (;;)
				pause();
		}
		out("VM-OP %d %s %d %s", lineno, r ? "fail" : "ok", r ? errno : 0, line);
		if (r)
			ok = 0;
	}
	return ok;
}

int main(void)
{
	struct utsname u;
	int ok;

	mkdir("/dev", 0755);
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	con = fopen("/dev/ttyS0", "w");
	if (!con)
		con = fopen("/dev/console", "w");
	if (!con)
		power_off();
	uname(&u);
	out("VM-UP %s", u.release);
	mkdir(MNT, 0755);
	/* The top-level tree, whatever the default subvolume is. */
	if (mount("/dev/vda", MNT, "btrfs", 0, "subvolid=5")) {
		out("VM-MOUNT fail %d", errno);
		kmsg();
		out("VM-DONE fail");
		power_off();
	}
	out("VM-MOUNT ok 0");
	ok = run_script();
	list_dir(MNT);
	if (umount(MNT)) {
		out("VM-ERR umount: %d", errno);
		ok = 0;
	}
	kmsg();
	out("VM-DONE %s", ok && list_ok ? "ok" : "fail");
	power_off();
	return 0;
}
