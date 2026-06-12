#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large barrier_smoke_x86_64.c -o barrier_smoke_x86_64
