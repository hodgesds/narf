#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large mcore_smoke_x86_64.c -o mcore_smoke_x86_64
