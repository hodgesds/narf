#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large pv_smoke_x86_64.c -o pv_smoke_x86_64
