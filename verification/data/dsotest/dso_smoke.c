/* Multi-DSO dynamic-linking smoke. Links libb + liba + libc dynamically
 * (interp = /lib/ld-musl-x86_64.so.1, RUNPATH /lib). b_compute drives a
 * cross-DSO call chain (main -> libb::b_compute -> liba::a_add) and
 * cross-DSO global data (a_global), resolved by ld-musl loading the .so's
 * the kernel seeded into /lib via file-backed mmap. Token "dso-ok". */
#include <unistd.h>
#include <string.h>
extern int b_compute(int);
static void w(const char *s) { write(1, s, strlen(s)); }
int main(void) {
    int r = b_compute(42); /* (42 + 100) + 100 = 242 */
    if (r != 242) { w("dso-fail: compute\n"); return 1; }
    w("dso-ok\n");
    return 0;
}
