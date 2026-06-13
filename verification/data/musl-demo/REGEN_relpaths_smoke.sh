#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large relpaths_smoke_x86_64.c -o relpaths_smoke_x86_64
