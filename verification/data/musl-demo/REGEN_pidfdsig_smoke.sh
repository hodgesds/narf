#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large pidfdsig_smoke_x86_64.c -o pidfdsig_smoke_x86_64
