/* Leaf shared library: a function plus exported global data. Part of the
 * multi-DSO chain main -> libb -> liba -> libc that dso_smoke exercises
 * (cross-DSO calls + R_X86_64_GLOB_DAT against a_global). */
int a_global = 100;
int a_add(int x) { return x + a_global; }
