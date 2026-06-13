#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large consoletty_smoke_x86_64.c -o consoletty_smoke_x86_64
