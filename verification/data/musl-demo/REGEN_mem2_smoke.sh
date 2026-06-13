#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large mem2_smoke_x86_64.c -o mem2_smoke_x86_64
