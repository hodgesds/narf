#!/bin/sh
# Generic Alpine-chroot launcher embedded by verification/build.rs
# (NARF_CHROOT_RUN_ELF_X86_64). CI uses the checked-in binary, not this
# script, so regenerate after editing chroot_run.c and commit the binary.
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large chroot_run.c -o chroot_run_x86_64
