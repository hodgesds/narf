#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large accept4_smoke_x86_64.c -o accept4_smoke_x86_64
