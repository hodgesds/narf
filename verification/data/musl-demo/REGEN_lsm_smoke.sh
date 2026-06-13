#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large lsm_smoke_x86_64.c -o lsm_smoke_x86_64
