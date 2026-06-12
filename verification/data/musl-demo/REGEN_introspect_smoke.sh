#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large introspect_smoke_x86_64.c -o introspect_smoke_x86_64
