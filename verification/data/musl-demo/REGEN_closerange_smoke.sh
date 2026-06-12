#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large closerange_smoke_x86_64.c -o closerange_smoke_x86_64
