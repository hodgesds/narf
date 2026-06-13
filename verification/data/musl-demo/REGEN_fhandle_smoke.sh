#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large fhandle_smoke_x86_64.c -o fhandle_smoke_x86_64
