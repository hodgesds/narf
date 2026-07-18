#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large strace_smoke_x86_64.c -o strace_smoke_x86_64
