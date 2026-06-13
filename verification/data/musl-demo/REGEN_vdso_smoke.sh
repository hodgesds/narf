#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large vdso_smoke_x86_64.c -o vdso_smoke_x86_64
