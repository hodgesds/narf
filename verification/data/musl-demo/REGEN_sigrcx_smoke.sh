#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large sigrcx_smoke_x86_64.c -o sigrcx_smoke_x86_64
