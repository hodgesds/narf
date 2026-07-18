#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large sigrt_smoke_x86_64.c -o sigrt_smoke_x86_64
