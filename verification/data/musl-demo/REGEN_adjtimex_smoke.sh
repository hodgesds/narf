#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large adjtimex_smoke_x86_64.c -o adjtimex_smoke_x86_64
