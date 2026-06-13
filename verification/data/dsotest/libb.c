/* Middle shared library: depends on liba (calls a_add, reads a_global) and
 * is itself called by the main program — a two-deep DT_NEEDED chain with
 * cross-DSO function + data relocations resolved by ld-musl. */
extern int a_add(int);
extern int a_global;
int b_compute(int x) { return a_add(x) + a_global; } /* (x + 100) + 100 */
