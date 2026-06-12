#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large xattr_smoke_x86_64.c -o xattr_smoke_x86_64
