/* Dynamic-linked musl hello-world for the NARF linux-compat demo.
 *
 * Same C source shape as the static version (hello_musl_x86_64.c),
 * but linked dynamically against ld-musl-x86_64.so.1. Compared to
 * the static binary's `__libc_start_main → main` path, this one
 * adds a substantial preamble: the kernel reads PT_INTERP, loads
 * ld-musl at INTERP_BIAS, applies its relocations, and jumps to
 * ld-musl's entry. ld-musl then:
 *
 *   1. Reads its OWN segments + maps any DT_NEEDED libraries
 *      (none here — pure libc dependency).
 *   2. Processes the program's R_X86_64_RELATIVE / GLOB_DAT /
 *      JUMP_SLOT relocations.
 *   3. Runs DT_INIT / .init_array.
 *   4. Sets up TLS via R_X86_64_TPOFF64 / DTPOFF64.
 *   5. Jumps to the program's entry point.
 *
 * This is the path Wave-75 plumbed but never end-to-end tested
 * against a real binary. Every relocation form mentioned above
 * exists in this binary's .rela.dyn / .rela.plt — `readelf -r
 * hello_musl_dyn_x86_64` enumerates them.
 *
 * Rebuild via REGEN_musl_dyn.sh in this directory (requires
 * musl-gcc).
 */

#include <unistd.h>

int main(void) {
    static const char msg[] = "hello from musl dyn\n";
    write(1, msg, sizeof(msg) - 1);
    return 0;
}
