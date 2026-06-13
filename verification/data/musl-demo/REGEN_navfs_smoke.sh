#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large navfs_smoke_x86_64.c -o navfs_smoke_x86_64
