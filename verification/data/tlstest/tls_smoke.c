/* Per-DSO TLS smoke. Links libtls.so dynamically and reads/writes its
 * thread-local state across the call boundary: the counter increments from
 * its initial value, the array sums correctly, and a write is visible on a
 * later read — proving ld-musl set up the DSO's TLS block + __tls_get_addr
 * on NARF. Token "tls-ok". */
#include <unistd.h>
#include <string.h>
extern int t_bump(void);
extern long t_sum(void);
extern void t_set(int, long);
static void w(const char *s) { write(1, s, strlen(s)); }
int main(void) {
    if (t_bump() != 8 || t_bump() != 9) { w("tls-fail: counter\n"); return 1; }
    if (t_sum() != 100) { w("tls-fail: sum\n"); return 1; } /* 10+20+30+40 */
    t_set(0, 1000);
    if (t_sum() != 1090) { w("tls-fail: setsum\n"); return 1; } /* 1000+20+30+40 */
    w("tls-ok\n");
    return 0;
}
