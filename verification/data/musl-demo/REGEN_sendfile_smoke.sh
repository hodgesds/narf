#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large sendfile_smoke_x86_64.c -o sendfile_smoke_x86_64
