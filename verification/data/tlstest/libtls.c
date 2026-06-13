/* Shared library exporting thread-local state via functions. Forces
 * general-dynamic TLS: the DSO's __thread vars are reached through
 * __tls_get_addr against a per-module TLS block ld-musl sets up at load —
 * the cross-DSO TLS path NARF's single-shared-library programs never hit. */
__thread int t_counter = 7;
__thread long t_data[4] = {10, 20, 30, 40};
int t_bump(void) { return ++t_counter; }       /* 8, 9, 10, ... */
long t_sum(void) { return t_data[0] + t_data[1] + t_data[2] + t_data[3]; }
void t_set(int i, long v) { t_data[i] = v; }
