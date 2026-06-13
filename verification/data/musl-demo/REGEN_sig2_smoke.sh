#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large sig2_smoke_x86_64.c -o sig2_smoke_x86_64
