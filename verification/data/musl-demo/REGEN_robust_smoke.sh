#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large robust_smoke_x86_64.c -o robust_smoke_x86_64
