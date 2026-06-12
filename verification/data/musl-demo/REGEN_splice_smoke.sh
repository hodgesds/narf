#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large splice_smoke_x86_64.c -o splice_smoke_x86_64
