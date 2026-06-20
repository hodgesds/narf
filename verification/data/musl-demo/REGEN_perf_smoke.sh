#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large perf_smoke_x86_64.c -o perf_smoke_x86_64
