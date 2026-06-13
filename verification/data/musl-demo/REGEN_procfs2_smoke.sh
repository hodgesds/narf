#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large procfs2_smoke_x86_64.c -o procfs2_smoke_x86_64
