#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large fsmisc_smoke_x86_64.c -o fsmisc_smoke_x86_64
