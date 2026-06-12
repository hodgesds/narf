#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large xattr2_smoke_x86_64.c -o xattr2_smoke_x86_64
