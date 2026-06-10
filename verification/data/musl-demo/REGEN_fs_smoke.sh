#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large fs_smoke_x86_64.c -o fs_smoke_x86_64
