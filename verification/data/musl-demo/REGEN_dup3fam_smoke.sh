#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large dup3fam_smoke_x86_64.c -o dup3fam_smoke_x86_64
