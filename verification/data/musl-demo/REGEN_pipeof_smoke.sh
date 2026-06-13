#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large pipeof_smoke_x86_64.c -o pipeof_smoke_x86_64
