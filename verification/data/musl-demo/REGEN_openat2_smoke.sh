#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large openat2_smoke_x86_64.c -o openat2_smoke_x86_64
