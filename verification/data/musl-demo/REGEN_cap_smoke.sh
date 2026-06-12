#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large cap_smoke_x86_64.c -o cap_smoke_x86_64
