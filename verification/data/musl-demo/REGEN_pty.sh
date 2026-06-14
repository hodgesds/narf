#!/bin/sh
# Documents the recipe; the actual build is done from the `.c` by
# verification/build.rs (uniform static-PIE list) into OUT_DIR — there is
# no committed binary. This mirrors that recipe for manual inspection.
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large pty_smoke_x86_64.c -o pty_smoke_x86_64
