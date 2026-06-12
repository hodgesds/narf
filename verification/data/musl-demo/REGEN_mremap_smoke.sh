#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large mremap_smoke_x86_64.c -o mremap_smoke_x86_64
