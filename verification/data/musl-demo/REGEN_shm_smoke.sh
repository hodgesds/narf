#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large shm_smoke_x86_64.c -o shm_smoke_x86_64
