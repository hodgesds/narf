#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large schedattr_smoke_x86_64.c -o schedattr_smoke_x86_64
