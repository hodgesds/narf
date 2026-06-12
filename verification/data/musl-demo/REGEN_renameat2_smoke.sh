#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large renameat2_smoke_x86_64.c -o renameat2_smoke_x86_64
